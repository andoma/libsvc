
PKG_CONFIG ?= pkg-config

libsvc_SRCS += \
	libsvc.c \
	misc.c \
	task.c \
	htsbuf.c \
	htsmsg.c \
	htsmsg_json.c \
	htsmsg_binary.c \
	json.c \
	dbl.c \
	dial.c \
	utf8.c \
	tcp.c \
	trace.c \
	irc.c \
	cfg.c \
	cmd.c \
	talloc.c \
	memstream.c \
	sock.c \
	ntv.c \
	ntv_json.c \
	ntv_binary.c \
	ntv_msgpack.c \
	ntv_cbor.c \
	intvec.c \
	strvec.c \
	murmur3.c \
	mbuf.c \
	trap.c \
	err.c \

libsvc_INCS += \
	libsvc.h \
	misc.h \
	task.h \
	htsbuf.h \
	htsmsg.h \
	htsmsg_json.h \
	htsmsg_binary.h \
	json.h \
	dbl.h \
	dial.h \
	utf8.h \
	tcp.h \
	trace.h \
	irc.h \
	cfg.h \
	cmd.h \
	talloc.h \
	memstream.h \
	sock.h \
	intvec.h \
	strvec.h \
	init.h \
	murmur3.h \
	mbuf.h \

CFLAGS  += $(shell $(PKG_CONFIG) --cflags openssl)
LDFLAGS += $(shell $(PKG_CONFIG) --libs openssl)

ifeq ($(shell uname),Linux)
LDFLAGS += -ldl #for trap handler
endif

##############################################################
# Curl
##############################################################
ifeq (${WITH_CURL},yes)

CFLAGS  += -DWITH_CURL

ifeq ($(shell uname),Darwin)
LDFLAGS += -lcurl -lz -liconv
endif

ifeq ($(shell uname),Linux)
CFLAGS  += $(shell pkg-config --cflags libcurl)
LDFLAGS += $(shell pkg-config --libs libcurl)
endif

libsvc_SRCS += urlshorten.c
libsvc_SRCS += http_client.c
libsvc_SRCS += curlhelpers.c

libsvc_INCS += urlshorten.h
libsvc_INCS += http_client.h
libsvc_INCS += curlhelpers.h
endif

##############################################################
# MYSQL
##############################################################

ifeq (${WITH_MYSQL},yes)
libsvc_SRCS    +=  db.c
libsvc_INCS    +=  db.h
CFLAGS  += $(shell mysql_config --cflags) -DWITH_MYSQL
LDFLAGS += $(shell mysql_config --libs_r)
endif

##############################################################
# Websocket client
##############################################################

ifeq (${WITH_WS_CLIENT},yes)
libsvc_SRCS    +=  websocket_client.c
libsvc_INCS    +=  websocket_client.h
WITH_WEBSOCKET := yes
CFLAGS += -DWITH_WS_CLIENT
endif

##############################################################
# HTTP Server
##############################################################

ifeq (${WITH_HTTP_SERVER},yes)
libsvc_SRCS    += http.c http_parser.c
libsvc_INCS    += http.h http_parser.h
WITH_ASYNCIO   := yes
WITH_WEBSOCKET := yes
CFLAGS += -DWITH_HTTP_SERVER
LDFLAGS += -lz
endif

##############################################################
# TCP server
##############################################################

ifeq (${WITH_TCP_SERVER},yes)
CFLAGS +=  -DWITH_TCP_SERVER
libsvc_SRCS    +=  tcp_server.c
endif

##############################################################
# AsyncIO
##############################################################

ifeq (${WITH_ASYNCIO},yes)
libsvc_SRCS +=  asyncio.c
libsvc_INCS +=  asyncio.h
CFLAGS +=  -DWITH_ASYNCIO
endif

##############################################################
# Control socket
##############################################################
ifeq (${WITH_CTRLSOCK},yes)
libsvc_SRCS +=  ctrlsock.c
libsvc_INCS +=  ctrlsock.h
CFLAGS += -DWITH_CTRLSOCK
endif

##############################################################
# Websocket common
##############################################################

ifeq (${WITH_WEBSOCKET},yes)
libsvc_SRCS    += websocket.c
libsvc_INCS    += websocket.h
LDFLAGS += -lz
endif
