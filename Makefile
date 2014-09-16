#
# Makefile to build shared library of libsvc
#

MAJOR_VERSION := 0
MINOR_VERSION := 1
PATCH_VERSION := 0

FULL_VERSION := ${MAJOR_VERSION}.${MINOR_VERSION}.${PATCH_VERSION}

prefix ?= /usr/local

WITH_CURL := yes
WITH_HTTP_SERVER := yes
WITH_WS_SERVER := yes

include sources.mk

OBJS=    $(libsvc_SRCS:%.c=%.o)
DEPS=    ${OBJS:%.o=%.d}

CFLAGS += -Wall -Werror -fPIC -O2 -g
LIB = libsvc.so

${LIB}: ${OBJS}  Makefile sources.mk
	${CC} -shared -o ${LIB} ${OBJS}

%.o: %.c Makefile sources.mk
	${CC} -MD -MP ${CFLAGS} -c -o $@ $<

clean:
	rm -f ${LIB} *~ *.o *.d

install:
	mkdir -p $(DESTDIR)$(prefix)/lib
	install -T ${LIB} $(DESTDIR)$(prefix)/lib/${LIB}.${FULL_VERSION}
	ln -sf ${LIB}.${FULL_VERSION} $(DESTDIR)$(prefix)/lib/${LIB}.${MAJOR_VERSION}
	ln -sf ${LIB}.${MAJOR_VERSION} $(DESTDIR)$(prefix)/lib/${LIB}

	mkdir -p $(DESTDIR)$(prefix)/include/libsvc

	for file in ${libsvc_INCS}; do \
		 install $${file} $(DESTDIR)$(prefix)/include/libsvc ; \
	done

-include $(DEPS)

