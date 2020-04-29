#include <string.h>
#include <pthread.h>
#include <openssl/evp.h>

#include "mbuf.h"

#include "cookie.h"
#include "misc.h"

#define COOKIE_KEY_LEN   16
#define COOKIE_NONCE_LEN 12
#define COOKIE_TAG_LEN   16


struct cookie_engine {

  EVP_CIPHER_CTX *enc;
  EVP_CIPHER_CTX *dec;

  pthread_mutex_t enc_mutex;

  pthread_mutex_t dec_mutex;
};



cookie_engine_t *
cookie_engine_create(const char *secret, const char *salt, int pbkdf2_rounds)
{
  uint8_t key[COOKIE_KEY_LEN];

  if(!PKCS5_PBKDF2_HMAC(secret, strlen(secret),
                        (const uint8_t *)salt, salt ? strlen(salt) : 0,
                        pbkdf2_rounds,
                        EVP_sha256(), sizeof(key), key)) {
    return NULL;
  }

  cookie_engine_t *ce = calloc(1, sizeof(cookie_engine_t));

  ce->enc = EVP_CIPHER_CTX_new();
  EVP_EncryptInit_ex(ce->enc, EVP_aes_128_gcm(), NULL, NULL, NULL);
  EVP_CIPHER_CTX_ctrl(ce->enc, EVP_CTRL_GCM_SET_IVLEN, COOKIE_NONCE_LEN, NULL);
  EVP_CIPHER_CTX_ctrl(ce->enc, EVP_CTRL_GCM_SET_TAG, COOKIE_TAG_LEN, NULL);
  EVP_EncryptInit_ex(ce->enc, NULL, NULL, key, NULL);

  ce->dec = EVP_CIPHER_CTX_new();
  EVP_EncryptInit_ex(ce->dec, EVP_aes_128_gcm(), NULL, NULL, NULL);
  EVP_CIPHER_CTX_ctrl(ce->dec, EVP_CTRL_GCM_SET_IVLEN, COOKIE_NONCE_LEN, NULL);
  EVP_CIPHER_CTX_ctrl(ce->dec, EVP_CTRL_GCM_SET_TAG, COOKIE_TAG_LEN, NULL);
  EVP_EncryptInit_ex(ce->dec, NULL, NULL, key, NULL);

  pthread_mutex_init(&ce->enc_mutex, NULL);
  pthread_mutex_init(&ce->dec_mutex, NULL);
  return ce;
}

void
cookie_engine_destroy(cookie_engine_t *ce)
{
  pthread_mutex_destroy(&ce->enc_mutex);
  pthread_mutex_destroy(&ce->dec_mutex);
  EVP_CIPHER_CTX_free(ce->enc);
  EVP_CIPHER_CTX_free(ce->dec);
  free(ce);
}


char *
cookie_encode(cookie_engine_t *ce, const ntv_t *msg)
{
  if(ce == NULL || msg == NULL)
    return NULL;

  scoped_mbuf_t msg_plaintext = MBUF_INITIALIZER(msg_plaintext);
  ntv_binary_serialize(msg, &msg_plaintext);

  const void *pt = mbuf_pullup(&msg_plaintext, msg_plaintext.mq_size);

  const size_t encrypted_len =
    COOKIE_NONCE_LEN + COOKIE_TAG_LEN + msg_plaintext.mq_size;

  uint8_t *encrypted = alloca(encrypted_len);
  get_random_bytes(encrypted, COOKIE_NONCE_LEN);

  pthread_mutex_lock(&ce->enc_mutex);
  if(EVP_EncryptInit_ex(ce->enc, NULL, NULL, NULL, encrypted) != 1) {
    pthread_mutex_unlock(&ce->enc_mutex);
    return NULL;
  }

  int outlen = 0;
  if(EVP_EncryptUpdate(ce->enc, encrypted + COOKIE_NONCE_LEN + COOKIE_TAG_LEN,
                       &outlen, pt, msg_plaintext.mq_size) != 1) {
    pthread_mutex_unlock(&ce->enc_mutex);
    return NULL;
  }

  int tmplen = 0;
  if(EVP_EncryptFinal_ex(ce->enc,
                         encrypted + COOKIE_NONCE_LEN + COOKIE_TAG_LEN,
                         &tmplen) != 1) {
    pthread_mutex_unlock(&ce->enc_mutex);
    return NULL;
  }

  if(EVP_CIPHER_CTX_ctrl(ce->enc, EVP_CTRL_CCM_GET_TAG, COOKIE_TAG_LEN,
                         encrypted + COOKIE_NONCE_LEN) != 1) {
    pthread_mutex_unlock(&ce->enc_mutex);
    return NULL;
  }

  pthread_mutex_unlock(&ce->enc_mutex);
  return base64_encode_a(encrypted, encrypted_len, BASE64_STANDARD);
}


ntv_t *
cookie_decode(cookie_engine_t *ce, const char *str)
{
  if(ce == NULL || str == NULL)
    return NULL;

  const size_t len = strlen(str);
  uint8_t *bin = alloca(len);
  int binlen = base64_decode(bin, str, len);
  if(binlen == -1)
    return NULL;

  if(binlen < COOKIE_NONCE_LEN + COOKIE_TAG_LEN + 1)
    return NULL;

  pthread_mutex_lock(&ce->dec_mutex);

  if(EVP_DecryptInit_ex(ce->dec, NULL, NULL, NULL, bin) != 1) {
    pthread_mutex_unlock(&ce->dec_mutex);
    return NULL;
  }

  if(EVP_CIPHER_CTX_ctrl(ce->dec, EVP_CTRL_CCM_SET_TAG, COOKIE_TAG_LEN,
                         bin + COOKIE_NONCE_LEN) != 1) {
    pthread_mutex_unlock(&ce->dec_mutex);
    return NULL;
  }

  uint8_t *plaintext = alloca(len);
  int outlen = 0;
  int rv = EVP_DecryptUpdate(ce->dec, plaintext, &outlen,
                             bin + COOKIE_NONCE_LEN + COOKIE_TAG_LEN,
                             binlen - COOKIE_NONCE_LEN - COOKIE_TAG_LEN);
  pthread_mutex_unlock(&ce->dec_mutex);

  if(rv <= 0)
    return NULL;

  return ntv_binary_deserialize(plaintext, outlen);
}
