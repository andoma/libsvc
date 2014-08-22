.DEFAULT_GOAL := ${PROG}

prefix ?= /usr/local


CFLAGS  += -Wall -Werror -Wwrite-strings -Wno-deprecated-declarations 
CFLAGS  += -Wmissing-prototypes -std=gnu99 -DPROGNAME=\"${PROGNAME}\"

SRCS += \
	libsvc/libsvc.c \
	libsvc/misc.c \
	libsvc/task.c \
	libsvc/htsbuf.c \
	libsvc/htsmsg.c \
	libsvc/htsmsg_json.c \
	libsvc/htsmsg_binary.c \
	libsvc/json.c \
	libsvc/dbl.c \
	libsvc/dial.c \
	libsvc/utf8.c \
	libsvc/tcp.c \
	libsvc/trace.c \
	libsvc/irc.c \
	libsvc/cfg.c \
	libsvc/cmd.c \
	libsvc/talloc.c \
	libsvc/memstream.c \

##############################################################
# Curl
##############################################################
ifeq (${WITH_CURL},yes)

ifeq ($(shell uname),Darwin)
LDFLAGS += -lcurl -lssh2 -lz -liconv
endif

ifeq ($(shell uname),Linux)
CFLAGS  += $(shell pkg-config --cflags libcurl)
LDFLAGS += $(shell pkg-config --libs libcurl)
endif

SRCS += libsvc/urlshorten.c
SRCS += libsvc/curlhelpers.c
endif

##############################################################
# MYSQL
##############################################################

ifeq (${WITH_MYSQL},yes)
SRCS    +=  libsvc/db.c
CFLAGS  += $(shell mysql_config --cflags) -DWITH_MYSQL
LDFLAGS += $(shell mysql_config --libs_r)
endif

##############################################################
# HTTP Server
##############################################################

ifeq (${WITH_HTTP_SERVER},yes)
SRCS    +=  libsvc/http.c
WITH_TCP_SERVER := yes
CFLAGS += -DWITH_HTTP_SERVER
endif

##############################################################
# TCP server
##############################################################

ifeq (${WITH_TCP_SERVER},yes)
CFLAGS +=  -DWITH_TCP_SERVER
SRCS    +=  libsvc/tcp_server.c
endif

##############################################################
# AsyncIO
##############################################################

ifeq (${WITH_ASYNCIO},yes)
SRCS +=  libsvc/asyncio.c
endif

##############################################################
# libgit2
##############################################################

ifeq (${WITH_LIBGIT2},yes)
CFLAGS +=  -DWITH_LIBGIT2
ALLDEPS += ${BUILDDIR}/libgit2/include/git2.h
CFLAGS  += -I${BUILDDIR}/libgit2/include/
LDFLAGS += -L${BUILDDIR}/libgit2/lib -lgit2 -lssh2

${BUILDDIR}/libgit2/include/git2.h:
	mkdir -p ${BUILDDIR}/libgit2/build
	cd ${BUILDDIR}/libgit2/build && cmake ${CURDIR}/libgit2 -DCMAKE_INSTALL_PREFIX=${BUILDDIR}/libgit2 -DBUILD_SHARED_LIBS=OFF -DTHREADSAFE=ON -DUSE_SSH=ON
	cd ${BUILDDIR}/libgit2/build && cmake --build . --target install
endif


##############################################################
# Control socket
##############################################################
ifeq (${WITH_CTRLSOCK},yes)
SRCS +=  libsvc/ctrlsock.c
CFLAGS += -DWITH_CTRLSOCK
endif


##############################################################
# Final linker stuff
##############################################################

LDFLAGS += -lssl -lcrypto -lbz2 -lpthread -lm

ifeq ($(shell uname),Linux)
LDFLAGS += -lrt
endif

##############################################################

ALLDEPS += libsvc/libsvc.mk Makefile

OBJS=    $(SRCS:%.c=$(BUILDDIR)/%.o)
DEPS=    ${OBJS:%.o=%.d}

# Common CFLAGS for all files
CFLAGS_com  = -g -funsigned-char -D_FILE_OFFSET_BITS=64
CFLAGS_com += -I${BUILDDIR} -I${CURDIR}
CFLAGS_opt = -O2


$(BUILDDIR)/bundles/%.o: $(BUILDDIR)/bundles/%.c $(ALLDEPS)
	$(CC) ${CFLAGS} ${CFLAGS_com} ${CFLAGS_opt} -c -o $@ $<

$(BUILDDIR)/bundles/%.c: % $(CURDIR)/libsvc/mkbundle $(ALLDEPS)
	@mkdir -p $(dir $@)
	$(MKBUNDLE) -o $@ -s $< -d  ${BUILDDIR}/bundles/$<.d -p $<

# File bundles
BUNDLES += $(sort $(BUNDLES-yes))
BUNDLE_SRCS=$(BUNDLES:%=$(BUILDDIR)/bundles/%.c)
BUNDLE_DEPS=$(BUNDLE_SRCS:%.c=%.d)
BUNDLE_OBJS=$(BUNDLE_SRCS:%.c=%.o)
.PRECIOUS: ${BUNDLE_SRCS}

MKBUNDLE = $(CURDIR)/libsvc/mkbundle

all: ${PROG} ${PROG}.installable

${PROG}: $(OBJS) $(ALLDEPS) ${BUILDDIR}/libsvc/filebundle_disk.o
	@mkdir -p $(dir $@)
	$(CC) -o $@ $(OBJS) ${BUILDDIR}/libsvc/filebundle_disk.o $(LDFLAGS) ${LDFLAGS_cfg}

${PROG}.installable: $(OBJS) $(BUNDLE_OBJS) $(ALLDEPS) ${BUILDDIR}/libsvc/filebundle_embedded.o
	@mkdir -p $(dir $@)
	$(CC) -o $@ $(OBJS) $(BUNDLE_OBJS) ${BUILDDIR}/libsvc/filebundle_embedded.o $(LDFLAGS) ${LDFLAGS_cfg}

${BUILDDIR}/%.o: %.c  $(ALLDEPS)
	@mkdir -p $(dir $@)
	$(CC) -MD -MP $(CFLAGS_com) $(CFLAGS) ${CFLAGS_opt} -c -o $@ $(CURDIR)/$<

.PHONY:	clean distclean

clean:
	rm -rf ${BUILDDIR}/src
	find . -name "*~" -print0 | xargs -0 rm -f

distclean: clean
	rm -rf ${BUILDDIR}

