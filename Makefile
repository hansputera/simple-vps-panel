# VPS Panel (C edition)
#
# make            production build (musl static) -> build/panel-musl
# make glibc      glibc dynamic fallback         -> build/panel-glibc
# make test       throwaway test instance        -> build/panel-test (port 9090)
# make run-test   build and start the test instance
# make deploy     stop panel-c, install build/panel-musl as the live binary, start
# make clean      remove build/
#
# The musl build needs musl-tools and libmicrohttpd compiled static for musl.
# If the library is missing, make downloads and builds it first (MHD_VER).

CC_MUSL   ?= musl-gcc
CC_GLIBC  ?= gcc

BASE_DIR  ?= /opt/caddy-panel-c
MHD_MUSL  ?= /opt/mhd-musl
MHD_VER   ?= 1.0.1

TESTBASE  ?= /tmp/ptest
TESTPORT  ?= 9090

CFLAGS_MUSL  ?= -Os -Wall -static -ffunction-sections -fdata-sections -Wl,--gc-sections
CFLAGS_GLIBC ?= -O2 -Wall

MHD_A = $(MHD_MUSL)/lib/libmicrohttpd.a

.PHONY: all glibc test run-test deploy clean help

all: build/panel-musl

help:
	@echo "make          production build (musl static)"
	@echo "make glibc    glibc dynamic fallback"
	@echo "make test     build test instance (port $(TESTPORT))"
	@echo "make run-test build and start the test instance"
	@echo "make deploy   install build/panel-musl as the live panel"
	@echo "make clean    remove build/"

# libmicrohttpd static for musl, built from source on first use
$(MHD_A):
	@echo ">> $(MHD_A) not found, building libmicrohttpd $(MHD_VER) for musl..."
	rm -rf /tmp/mhd-build
	mkdir -p /tmp/mhd-build
	wget -q https://ftp.gnu.org/gnu/libmicrohttpd/libmicrohttpd-$(MHD_VER).tar.gz \
	    -O /tmp/mhd-build/mhd.tar.gz
	tar -xzf /tmp/mhd-build/mhd.tar.gz -C /tmp/mhd-build --strip-components=1
	cd /tmp/mhd-build && CC=$(CC_MUSL) CFLAGS="-Os -ffunction-sections -fdata-sections" \
	    ./configure --prefix=$(MHD_MUSL) --disable-shared --enable-static \
	    --disable-https --without-gnutls --disable-curl --disable-docs \
	    --disable-examples --disable-messages
	cd /tmp/mhd-build && make -j$$(nproc) && make install

build/panel-musl: panel.c compat/crypt.h compat/crypt_r.c $(MHD_A)
	@mkdir -p build
	$(CC_MUSL) $(CFLAGS_MUSL) -Icompat -I$(MHD_MUSL)/include \
	    -o $@ panel.c compat/crypt_r.c $(MHD_A)
	strip $@

build/panel-glibc: panel.c
	@mkdir -p build
	$(CC_GLIBC) $(CFLAGS_GLIBC) -o $@ panel.c -lmicrohttpd -lcrypt -lpthread

glibc: build/panel-glibc

# test instance: separate port, base dir and creds file, so the live panel
# and its password are never touched
build/panel-test: panel.c compat/crypt.h compat/crypt_r.c $(MHD_A)
	@mkdir -p build $(TESTBASE)
	$(CC_MUSL) $(CFLAGS_MUSL) -Icompat -I$(MHD_MUSL)/include \
	    -DPORT=$(TESTPORT) -DBASE='"$(TESTBASE)"' \
	    -DCREDS_PATH='"$(TESTBASE)/creds.txt"' \
	    -o $@ panel.c compat/crypt_r.c $(MHD_A)

test: build/panel-test

run-test: build/panel-test
	@pkill -x panel-test 2>/dev/null || true
	@cd $(TESTBASE) && setsid $(CURDIR)/build/panel-test </dev/null >/dev/null 2>&1 &
	@sleep 1
	@echo "test panel on http://127.0.0.1:$(TESTPORT), login: $(TESTBASE)/creds.txt"

deploy: build/panel-musl
	systemctl stop panel-c
	mv build/panel-musl $(BASE_DIR)/panel
	systemctl start panel-c
	@sleep 2
	@systemctl is-active panel-c

clean:
	rm -rf build
