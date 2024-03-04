#include "dns.h"

#include "strvec.h"
#include "bytestream.h"

#include <stdio.h>

int
dns_parse_name(strvec_t *out, size_t offset,
               const uint8_t *pkt, size_t pktlen)
{
  int used = 0;
  size_t prev_offset = offset;

  while(1) {
    if(offset + used + 1 > pktlen) {
      return 0;
    }

    int labellen = pkt[offset + used];
    if(labellen >= 0xc0)
      break;
    if(labellen >= 0x40)
      return 0;
    used++;
    if(labellen == 0)
      return used;

    if(offset + used >= pktlen) {
      return 0;
    }
    strvec_pushl(out, (const char *)pkt + offset + used, labellen);
    used += labellen;
  }

  offset += used;
  used += 2;

  while(1) {
    if(offset > pktlen)
      return 0;
    size_t off = rd16_be(pkt + offset) & 0x3fff;
    if(off >= prev_offset)
      return 0;
    offset = off;
    prev_offset = off;

    while(1) {
      if(offset + 1 > pktlen) {
        return 0;
      }

      int labellen = pkt[offset];
      if(labellen >= 0xc0)
        break;
      if(labellen >= 0x40)
        return 0;
      offset++;
      if(labellen == 0)
        return used;

      if(offset >= pktlen) {
        return 0;
      }
      strvec_pushl(out, (const char *)pkt + offset, labellen);
      offset += labellen;
    }
  }
}


