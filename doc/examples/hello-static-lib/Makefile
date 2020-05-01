# SPDX-License-Identifier: MIT
#
# Copyright (C) 2013 Jérémie Galarneau <jeremie.galarneau@efficios.com>
#
# This Makefile is not using automake so that users may see how to build
# a program with tracepoint provider probes compiled as static libraries.
#
# This makefile is purposefully kept simple to support GNU and BSD make.

LOCAL_CPPFLAGS += -I.
LIBS = -ldl -llttng-ust	# On Linux
#LIBS = -lc -llttng-ust	# On BSD
AM_V_P := :
AR ?= ar

all: hello

lttng-ust-provider-hello.o: tp.c ust_tests_hello.h
	@if $(AM_V_P); then set -x; else echo "  CC       $@"; fi; \
		$(CC) $(CPPFLAGS) $(LOCAL_CPPFLAGS) $(AM_CFLAGS) $(AM_CPPFLAGS) \
		$(CFLAGS) -c -o $@ $<

lttng-ust-provider-hello.a: lttng-ust-provider-hello.o
	@if $(AM_V_P); then set -x; else echo "  AR       $@"; fi; \
		$(AR) -rc $@ lttng-ust-provider-hello.o

hello.o: hello.c
	@if $(AM_V_P); then set -x; else echo "  CC       $@"; fi; \
		$(CC) $(CPPFLAGS) $(LOCAL_CPPFLAGS) $(AM_CFLAGS) $(AM_CPPFLAGS) \
		$(CFLAGS) -c -o $@ $<

hello: hello.o lttng-ust-provider-hello.a
	@if $(AM_V_P); then set -x; else echo "  CCLD     $@"; fi; \
		$(CC) -o $@ $(LDFLAGS) $(CPPFLAGS) $(AM_LDFLAGS) $(AM_CFLAGS) \
		$(CFLAGS) hello.o lttng-ust-provider-hello.a $(LIBS)

.PHONY: clean
clean:
	rm -f *.o *.a hello
