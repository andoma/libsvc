#
#  Copyright (C) 2014 Andreas Öman
#
#  This program is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program.  If not, see <http://www.gnu.org/licenses/>.
#


PROGNAME := example

WITH_HTTP_SERVER := yes
WITH_CTRL_SOCK   := yes
WITH_CURL        := yes
WITH_WS_CLIENT   := yes
WITH_ASYNCIO     := yes

CC=gcc

BUILD ?= $(shell uname)

-include mk/${BUILD}.mk

CSTANDARD  := gnu11
CFLAGS_opt := -O2

BUILDDIR = ${CURDIR}/build

PROG=${BUILDDIR}/${PROGNAME}

SRCS =  src/main.c \

LDFLAGS += -lz

install: ${PROG}
	install -D ${PROG} "${prefix}/bin/${PROGNAME}"
uninstall:
	rm -f "${prefix}/bin/${PROGNAME}" "${prefix}/bin/${PROGNAME}"

include libsvc/libsvc.mk
-include config.local
-include $(DEPS)

