/******************************************************************************
* Copyright (C) 2008 - 2014 Andreas Öman
*
* Permission is hereby granted, free of charge, to any person obtaining
* a copy of this software and associated documentation files (the
* "Software"), to deal in the Software without restriction, including
* without limitation the rights to use, copy, modify, merge, publish,
* distribute, sublicense, and/or sell copies of the Software, and to
* permit persons to whom the Software is furnished to do so, subject to
* the following conditions:
*
* The above copyright notice and this permission notice shall be
* included in all copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
* EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
* MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
* IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
* CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
* TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
* SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
******************************************************************************/

#pragma once

#include <stdio.h>
#include <stdarg.h>
#include <stddef.h>
#include <inttypes.h>
#include <sys/queue.h>

#define MBUF_DEFAULT_DATA_SIZE 4096

TAILQ_HEAD(mbuf_data_queue, mbuf_data);


typedef enum {
  // mbuf_data represents malloced memeory
  MBUF_MALLOC,

  // mbuf_data doesn't represent any data at all but rather when
  // this buffer is consumed the callback is invoked instead
  MBUF_CALLBACK
} mbuf_data_type_t;


typedef struct mbuf_data {
  TAILQ_ENTRY(mbuf_data) md_link;

  size_t md_data_len;  /* Number of valid bytes from md_data */
  size_t md_data_off;  /* Offset in data, used for partial reads */

  int md_flags;
  mbuf_data_type_t md_type;

  union {

    struct {
      uint8_t *md_data;
      size_t md_data_size; /* Size of allocation hb_data */
    };

    struct {
      void (*md_callback)(void *opaque);
      void *md_opaque;
    };
  };

} mbuf_data_t;



#define MBUF_SOM 0x1   /* Start-of-message */

typedef struct mbuf {
  struct mbuf_data_queue mq_buffers;
  size_t mq_size;
  size_t mq_alloc_size;
} mbuf_t;

#define	MBUF_INITIALIZER(m) \
  { { NULL, &(m).mq_buffers.tqh_first }, 0, MBUF_DEFAULT_DATA_SIZE }

void mbuf_data_free(mbuf_t *mq, mbuf_data_t *md);

void mbuf_init(mbuf_t *m);

void mbuf_set_chunk_size(mbuf_t *m, size_t s);

void mbuf_clear(mbuf_t *m);

#define scoped_mbuf_t mbuf_t __attribute__((cleanup(mbuf_clear)))

void mbuf_vqprintf(mbuf_t *m, const char *fmt, va_list ap);

void mbuf_qprintf(mbuf_t *m, const char *fmt, ...)
   __attribute__ ((format (printf, 2, 3)));

void mbuf_append(mbuf_t *m, const void *buf, size_t len);

// Set start-of-message flag and append
void mbuf_append_som(mbuf_t *mq, const void *buf, size_t len);

void mbuf_append_str(mbuf_t *m, const char *buf);

void mbuf_append_prealloc(mbuf_t *m, void *buf, size_t len);

void mbuf_append_callback(mbuf_t *mq, void (*cb)(void *opaque), void *opaque);

void mbuf_append_FILE(mbuf_t *m, FILE *fp);

void mbuf_prepend(mbuf_t *m, const void *buf, size_t len);

size_t mbuf_read(mbuf_t *m, void *buf, size_t len);

size_t mbuf_peek(mbuf_t *m, void *buf, size_t len);

size_t mbuf_peek_no_copy(mbuf_t *mq, const void **buf);

size_t mbuf_peek_tail(mbuf_t *mq, void *buf, size_t len);

size_t mbuf_drop(mbuf_t *m, size_t len);

size_t mbuf_drop_tail(mbuf_t *mq, size_t len);

int mbuf_find(mbuf_t *m, uint8_t v);

void mbuf_appendq(mbuf_t *m, mbuf_t *src);

// Write mbuf to file
int mbuf_write_FILE(mbuf_t *mq, FILE* fp);

void mbuf_prependq(mbuf_t *mq, mbuf_t *src);

void mbuf_copyq(mbuf_t *mq, const mbuf_t *src);

void mbuf_append_and_escape_xml(mbuf_t *m, const char *str);

void mbuf_append_and_escape_url(mbuf_t *m, const char *s);

void mbuf_append_and_escape_jsonstr(mbuf_t *m, const char *s,
                                    int escape_slash);

void mbuf_append_u8(mbuf_t *m, uint8_t u8);

void mbuf_append_u16_be(mbuf_t *m, uint16_t u16);

void mbuf_append_u32_be(mbuf_t *m, uint32_t u32);

void mbuf_dump_raw_stderr(mbuf_t *m);

void mbuf_hexdump(const char *prefix, mbuf_t *mq);

const void *mbuf_pullup(mbuf_t *mq, size_t bytes);

char *mbuf_clear_to_string(mbuf_t *mq)
  __attribute__((warn_unused_result));

int mbuf_deflate(mbuf_t *dst, mbuf_t *src, int level)
  __attribute__((warn_unused_result));

int mbuf_gzip(mbuf_t *dst, mbuf_t *src, int level)
  __attribute__((warn_unused_result));


/**
 * Group of queues for prioritized packet scheduling
 */

typedef struct mbuf_grp mbuf_grp_t;

typedef enum {
  MBUF_GRP_MODE_STRICT_PRIORITY = 0,
} mbuf_grp_mode_t;

mbuf_grp_t *mbuf_grp_create(mbuf_grp_mode_t mode);

void mbuf_grp_destroy(mbuf_grp_t *mg);

void mbuf_grp_append(mbuf_grp_t *mg, int queue,
                     const void *data, size_t len, int start_of_message);

void mbuf_grp_appendq(mbuf_grp_t *mg, int queue, mbuf_t *src);

size_t mbuf_grp_peek_no_copy(mbuf_grp_t *mg, const void **buf);

void mbuf_grp_drop(mbuf_grp_t *mg, size_t size);

size_t mbuf_grp_size(mbuf_grp_t *mg);

size_t mbuf_grp_size_for_queue(mbuf_grp_t *mg, int queue_index);
