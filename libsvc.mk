
libsvc_SRCS += \
	misc.c \
	htsbuf.c \
	htsmsg.c \
	htsmsg_json.c \
	htsmsg_binary.c \
	json.c \
	dbl.c \
	dial.c \
	utf8.c \
	tcp.c \
	http.c \
	trace.c \
	irc.c \
	cfg.c \
	urlshorten.c \
	ctrlsock.c \
	cmd.c \
	talloc.c \
	filebundle.c \
	asyncio.c \

libsvc_SRCS-${WITH_MYSQL} +=  db.c

libsvc_SRCS += ${libsvc_SRCS-yes}