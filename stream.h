#pragma once

#include <unistd.h>

typedef struct stream stream_t;

#define STREAM_CONNECT_F_SSL             0x1
#define STREAM_CONNECT_F_SSL_DONT_VERIFY 0x2
#define STREAM_DEBUG                     0x4
#define STREAM_CLOCK_MONOTONIC           0x8

stream_t *stream_connect(const char *hostname, int port,
                         int timeout_ms,
                         char *errbuf, size_t errlen,
                         int flags);

// Return number of bytes written or -1 on error (which sets errno)
ssize_t stream_write(stream_t *s, const void *data, size_t len);

#define STREAM_READ_F_ALL 0x1
// Return number of bytes read or -1 on error (which sets errno)
ssize_t stream_read(stream_t *s, void *data, size_t len, int flags);

// Same as above but with timeout (in µs since 1970)
ssize_t stream_read_timeout(stream_t *s, void *data, size_t len, int flags,
                            int64_t deadline);

void stream_close(stream_t *s);

void stream_shutdown(stream_t *s, int stop_reader);
