.DEFAULT_GOAL := ${PROG}

prefix ?= /usr/local


CFLAGS  += -Wall -Werror -Wwrite-strings -Wno-deprecated-declarations 
CFLAGS  += -Wmissing-prototypes -std=gnu99

CFLAGS  += $(shell pkg-config --cflags libcurl)
LDFLAGS += $(shell pkg-config --libs libcurl) -lssl -lcrypto -lbz2 -lpthread -lrt

SRCS += \
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
	libsvc/http.c \
	libsvc/trace.c \
	libsvc/irc.c \
	libsvc/cfg.c \
	libsvc/urlshorten.c \
	libsvc/ctrlsock.c \
	libsvc/cmd.c \
	libsvc/talloc.c \
	libsvc/filebundle.c \
	libsvc/asyncio.c \

SRCS-${WITH_MYSQL} +=  libsvc/db.c

# Various transformations
SRCS  += $(SRCS-yes)
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

$(info ${SRCS})
$(info ${OBJS})

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

