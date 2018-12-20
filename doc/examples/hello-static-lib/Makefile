# Copyright (C) 2013  Jérémie Galarneau <jeremie.galarneau@efficios.com>
#
# THIS MATERIAL IS PROVIDED AS IS, WITH ABSOLUTELY NO WARRANTY EXPRESSED
# OR IMPLIED. ANY USE IS AT YOUR OWN RISK.
#
# Permission is hereby granted to use or copy this program for any
# purpose, provided the above notices are retained on all copies.
# Permission to modify the code and to distribute modified code is
# granted, provided the above notices are retained, and a notice that
# the code was modified is included with the above copyright notice.
#
# This Makefile is not using automake so that users may see how to build
# a program with tracepoint provider probes compiled as static libraries.
#
# This makefile is purposefully kept simple to support GNU and BSD make.

LOCAL_CPPFLAGS += -I.
LIBS = -ldl -llttng-ust	# On Linux
#LIBS = -lc -llttng-ust	# On BSD
AM_V_P := :

all: hello

lttng-ust-provider-hello.o: tp.c ust_tests_hello.h
	@if $(AM_V_P); then set -x; else echo "  CC       $@"; fi; \
		$(CC) $(CPPFLAGS) $(LOCAL_CPPFLAGS) $(AM_CFLAGS) $(AM_CPPFLAGS) \
		$(CFLAGS) -c -o $@ $<

lttng-ust-provider-hello.a: lttng-ust-provider-hello.o
	@if $(AM_V_P); then set -x; else echo "  AR       $@"; fi; \
		ar -rc $@ lttng-ust-provider-hello.o

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
