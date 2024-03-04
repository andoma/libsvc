#pragma once

#include <stdint.h>
#include <stddef.h>

struct strvec;

int dns_parse_name(struct strvec *out, size_t offset,
                   const uint8_t *pkt, size_t pktlen);
