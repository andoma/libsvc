.DEFAULT_GOAL := ${PROG}

prefix ?= /usr/local

CSTANDARD ?= gnu99

CFLAGS  += -Wall -Werror -Wwrite-strings -Wno-deprecated-declarations 
CFLAGS  += -Wmissing-prototypes -std=${CSTANDARD} -DPROGNAME=\"${PROGNAME}\"

include libsvc/sources.mk

SRCS += ${libsvc_SRCS:%.c=libsvc/%.c}

##############################################################
# Final linker stuff
##############################################################

LDFLAGS += -lssl -lcrypto -lbz2 -lpthread -lm

ifeq ($(shell uname),Linux)
LDFLAGS += -lrt
endif

##############################################################

ALLDEPS += libsvc/libsvc.mk Makefile libsvc/sources.mk

OBJS +=  $(SRCS:%.c=$(BUILDDIR)/%.o)
DEPS +=  ${OBJS:%.o=%.d}

# Common CFLAGS for all files
CFLAGS_com  = -g -funsigned-char -D_FILE_OFFSET_BITS=64
CFLAGS_com += -I${BUILDDIR} -I${CURDIR}
CFLAGS_opt ?= -O2


$(BUILDDIR)/bundles/%.o: $(BUILDDIR)/bundles/%.c $(ALLDEPS)
	$(CC) ${CFLAGS} ${CFLAGS_com} ${CFLAGS_opt} -c -o $@ $<

$(BUILDDIR)/bundles/%.c: % $(CURDIR)/libsvc/mkbundle $(ALLDEPS)
	@mkdir -p $(dir $@)
	$(MKBUNDLE) -o $@ -s $< -d  ${BUILDDIR}/bundles/$<.d -p $<

$(BUILDDIR)/zbundles/%.o: $(BUILDDIR)/zbundles/%.c $(ALLDEPS)
	$(CC) ${CFLAGS} ${CFLAGS_com} ${CFLAGS_opt} -c -o $@ $<

$(BUILDDIR)/zbundles/%.c: % $(CURDIR)/libsvc/mkbundle $(ALLDEPS)
	@mkdir -p $(dir $@)
	$(MKBUNDLE) -z -o $@ -s $< -d ${BUILDDIR}/zbundles/$<.d -p $<

# File bundles
BUNDLES += $(sort $(BUNDLES-yes))
BUNDLE_SRCS=$(BUNDLES:%=$(BUILDDIR)/bundles/%.c)

ZBUNDLES += $(sort $(ZBUNDLES-yes))
ZBUNDLE_SRCS=$(ZBUNDLES:%=$(BUILDDIR)/zbundles/%.c)

DEPS += $(BUNDLE_SRCS:%.c=%.d) $(ZBUNDLE_SRCS:%.c=%.d)
BUNDLE_OBJS=$(BUNDLE_SRCS:%.c=%.o) $(ZBUNDLE_SRCS:%.c=%.o)
.PRECIOUS: ${BUNDLE_SRCS} ${ZBUNDLE_SRCS}


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

