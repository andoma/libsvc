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
#include <stdlib.h>

#include "mbuf.h"
#include "websocket.h"
#include "bytestream.h"


/**
 *
 */
void
websocket_free(websocket_state_t *state)
{
  free(state->packet);
  state->packet = NULL;
}

/**
 *
 */
int
websocket_build_hdr(uint8_t hdr[static WEBSOCKET_MAX_HDR_LEN], int opcode, size_t len, int compressed)
{
  int hlen;
  hdr[0] = 0x80 | (opcode & 0xf) | (compressed ? 0x40 : 0);
  if(len <= 125) {
    hdr[1] = len;
    hlen = 2;
  } else if(len < 65536) {
    hdr[1] = 126;
    hdr[2] = len >> 8;
    hdr[3] = len;
    hlen = 4;
  } else {
    hdr[1] = 127;
    wr64_be(hdr + 2, len);
    hlen = 10;
  }
  return hlen;
}



/**
 *
 */
void
websocket_append_hdr(mbuf_t *q, int opcode, size_t len)
{
  uint8_t hdr[14]; // max header length
  const int hlen = websocket_build_hdr(hdr, opcode, len, 0);
  mbuf_append(q, hdr, hlen);
}


/**
 *
 */
int
websocket_parse(mbuf_t *q,
                int (*cb)(void *opaque, int opcode, uint8_t **data, int len,
                          int flags),
                void *opaque, websocket_state_t *ws)
{
  uint8_t hdr[14]; // max header length
  while(1) {
    int p = mbuf_peek(q, &hdr, 14);
    const uint8_t *m;

    if(p < 2)
      return 0;
    const uint8_t fin        = hdr[0] & 0x80;
    const uint8_t compressed = hdr[0] & 0x40;
    const int opcode         = hdr[0] & 0xf;
    int64_t len              = hdr[1] & 0x7f;
    int hoff = 2;
    if(len == 126) {
      if(p < 4)
        return 0;
      len = hdr[2] << 8 | hdr[3];
      hoff = 4;
    } else if(len == 127) {
      if(p < 10)
        return 0;
      len = rd64_be(hdr + 2);
      hoff = 10;
    }

    if(hdr[1] & 0x80) {
      if(p < hoff + 4)
        return 0;
      m = hdr + hoff;

      hoff += 4;
    } else {
      m = NULL;
    }

    if(q->mq_size < hoff + len)
      return 0;

    mbuf_drop(q, hoff);

    if(opcode & 0x8) {
      // Ctrl frame
      uint8_t *p = malloc(len);
      if(p == NULL)
        return 1;

      mbuf_read(q, p, len);
      if(m != NULL) for(int i = 0; i < len; i++) p[i] ^= m[i&3];

      int err = cb(opaque, opcode, &p, len, 0);
      free(p);
      if(!err)
        continue;
      return 1;
    }

    // The four extra pad bytes are used for:
    //  pad[0] is always 0 so the websocket payload can be parsed as a string
    // or
    //  All four bytes can be used to append the deflate flush trailer
    void *r = realloc(ws->packet, ws->packet_size + len + 4);
    if(r == NULL)
      return 1;
    ws->packet = r;

    uint8_t *d = ws->packet + ws->packet_size;
    d[len] = 0;
    mbuf_read(q, d, len);

    if(m != NULL) for(int i = 0; i < len; i++) d[i] ^= m[i&3];

    if(opcode != 0) {
      ws->opcode = opcode;
      if(compressed) {
        ws->flags |= WS_MESSAGE_COMPRESSED;
      }
    }

    ws->packet_size += len;

    if(!fin)
      continue;

    int err = cb(opaque, ws->opcode, &ws->packet, ws->packet_size, ws->flags);
    ws->packet_size = 0;
    ws->flags = 0;
    if(!err)
      continue;
    return 1;
  }
}
