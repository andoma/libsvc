.DEFAULT_GOAL := ${PROG}

prefix ?= /usr/local


CFLAGS  += -Wall -Werror -Wwrite-strings -Wno-deprecated-declarations 
CFLAGS  += -Wmissing-prototypes -std=gnu99

SRCS += \
	libsvc/libsvc.c \
	libsvc/misc.c \
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
	libsvc/filebundle.c \


##############################################################
# Curl
##############################################################
ifeq (${WITH_CURL},yes)
CFLAGS  += $(shell pkg-config --cflags libcurl)
LDFLAGS += $(shell pkg-config --libs libcurl)
SRCS += libsvc/urlshorten.c
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
LDFLAGS += -L${BUILDDIR}/libgit2/lib -lgit2

${BUILDDIR}/libgit2/include/git2.h:
	mkdir -p ${BUILDDIR}/libgit2/build
	cd ${BUILDDIR}/libgit2/build && cmake ${CURDIR}/libgit2 -DCMAKE_INSTALL_PREFIX=${BUILDDIR}/libgit2 -DBUILD_SHARED_LIBS=OFF -DTHREADSAFE=ON
	cd ${BUILDDIR}/libgit2/build && cmake --build . --target install
endif


##############################################################
# Control socket
##############################################################
ifeq (${WITH_CTRLSOCK},yes)
SRCS +=  libsvc/ctrlsock.c
endif


##############################################################
# Final linker stuff
##############################################################

LDFLAGS += -lssl -lcrypto -lbz2 -lpthread -lrt -lm

##############################################################

OBJS=    $(SRCS:%.c=$(BUILDDIR)/%.o)
DEPS=    ${OBJS:%.o=%.d}

# Common CFLAGS for all files
CFLAGS_com  = -g -funsigned-char -O2 -D_FILE_OFFSET_BITS=64
CFLAGS_com += -I${BUILDDIR} -I${CURDIR}

$(BUILDDIR)/bundles/%.o: $(BUILDDIR)/bundles/%.c $(ALLDEPS)
	$(CC) $(CFLAGS_com) -c -o $@ $<

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

all: ${PROG}

${PROG}: $(OBJS) $(BUNDLE_OBJS) $(ALLDEPS)
	@mkdir -p $(dir $@)
	$(CC) -o $@ $(OBJS) $(BUNDLE_OBJS) $(LDFLAGS) ${LDFLAGS_cfg}

${BUILDDIR}/%.o: %.c  $(ALLDEPS)
	@mkdir -p $(dir $@)
	$(CC) -MD -MP $(CFLAGS_com) $(CFLAGS) -c -o $@ $(CURDIR)/$<

.PHONY:	clean distclean

clean:
	rm -rf ${BUILDDIR}/src
	find . -name "*~" -print0 | xargs -0 rm -f

distclean: clean
	rm -rf ${BUILDDIR}

