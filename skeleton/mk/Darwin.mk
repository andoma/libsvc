
HOMEBREW_LOC=$(shell dirname $(shell which brew))
HOMEBREW_PREFIX=$(shell (cd ${HOMEBREW_LOC}/.. && pwd))

PKG_CONFIG_PATH := ${HOMEBREW_PREFIX}/opt/openssl/lib/pkgconfig/
export PKG_CONFIG_PATH

CFLAGS_deps  := $(shell PKG_CONFIG_PATH='$(PKG_CONFIG_PATH)' pkg-config openssl  --cflags)

LDFLAGS := $(shell PKG_CONFIG_PATH='$(PKG_CONFIG_PATH)' pkg-config openssl --libs)

CFLAGS += ${CFLAGS_deps}
