
PKG_CONFIG ?= pkg-config

libsvc_SRCS += \
	libsvc.c \
	misc.c \
	task.c \
	htsbuf.c \
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
	ntv_xml.c \
	intvec.c \
	strvec.c \
	murmur3.c \
	mbuf.c \
	trap.c \
	err.c \
	aws.c \
	acme.c \
	fpipe.c \
	tbm.c \
	cookie.c \
	gcp.c \
	azure.c \


libsvc_INCS += \
	libsvc.h \
	misc.h \
	task.h \
	htsbuf.h \
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

ifeq (${WITH_OPENSSL},yes)
CFLAGS  += $(shell $(PKG_CONFIG) --cflags openssl) -DWITH_OPENSSL
LDFLAGS += $(shell $(PKG_CONFIG) --libs openssl)
endif



ifeq ($(shell uname),Linux)
LDFLAGS += -ldl #for trap handler
endif

libsvc_SRCS += http_client.c
libsvc_INCS += http_client.h

##############################################################
# Curl
##############################################################
ifeq (${WITH_CURL},yes)

CFLAGS  += -DWITH_CURL

ifeq ($(shell uname),Darwin)
LDFLAGS += -lcurl -lz -liconv
endif

ifeq ($(shell uname),Linux)
CFLAGS  += $(shell $(PKG_CONFIG) --cflags libcurl)
LDFLAGS += $(shell $(PKG_CONFIG) --libs libcurl)
endif

libsvc_SRCS += http_client_curl.c
libsvc_SRCS += curlhelpers.c

libsvc_INCS += curlhelpers.h

else

libsvc_SRCS += http_client_builtin.c
WITH_HTTP_PARSER := yes

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
libsvc_SRCS    +=  websocket_client.c http_parser.c
libsvc_INCS    +=  websocket_client.h
WITH_WEBSOCKET := yes
CFLAGS += -DWITH_WS_CLIENT
endif

##############################################################
# HTTP Server
##############################################################

ifeq (${WITH_HTTP_SERVER},yes)
libsvc_SRCS    += http.c
libsvc_INCS    += http.h
WITH_ASYNCIO   := yes
WITH_WEBSOCKET := yes
WITH_HTTP_PARSER := yes
CFLAGS += -DWITH_HTTP_SERVER
LDFLAGS += -lz
endif

ifeq (${WITH_HTTP_PARSER},yes)
libsvc_SRCS += http_parser.c
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
libsvc_SRCS +=  asyncio.c stream.c
libsvc_INCS +=  asyncio.h stream.h
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
