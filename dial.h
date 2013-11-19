#pragma once

#include "tcp.h"

tcp_stream_t *dial(const char *hostname, int port, int timeout, int ssl);
