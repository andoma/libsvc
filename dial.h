/******************************************************************************
* Copyright (C) 2013 - 2014 Andreas Öman
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

// Connection-establishment phases, reported through the optional callback
// passed to dialfd() / stream_connect_ex(). The values are shared up the
// stack (stream, http_client) so they can be forwarded without translation.
#define CONN_PHASE_RESOLVING  0
#define CONN_PHASE_CONNECTING 1
#define CONN_PHASE_TLS        2   // fired by the stream layer, not dialfd

// phase_cb may be NULL. It is invoked with CONN_PHASE_RESOLVING before the
// DNS lookup and CONN_PHASE_CONNECTING before the TCP connect attempts.
int dialfd(const char *hostname, int port, int timeout,
           char *errbuf, size_t errlen, int debug,
           void (*phase_cb)(void *opaque, int phase), void *phase_opaque);
