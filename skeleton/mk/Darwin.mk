
HOMEBREW_LOC=$(shell dirname $(shell which brew))
HOMEBREW_PREFIX=$(shell (cd ${HOMEBREW_LOC}/.. && pwd))

PKG_CONFIG_PATH := ${HOMEBREW_PREFIX}/opt/openssl/lib/pkgconfig/

PKG_CONFIG := PKG_CONFIG_PATH='$(PKG_CONFIG_PATH)' pkg-config

CFLAGS += ${CFLAGS_deps}
