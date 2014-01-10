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

ifdef AM_CC
	CC = $(AM_CC)
endif

LOCAL_CPPFLAGS += -I.
LIBS = -ldl -llttng-ust	# On Linux
#LIBS = -lc -llttng-ust	# On BSD

all: hello

lttng-ust-provider-hello.o: tp.c ust_tests_hello.h
	$(CC) $(CPPFLAGS) $(LOCAL_CPPFLAGS) $(CFLAGS) $(AM_CPPFLAGS) \
		$(AM_CFLAGS) -c -o $@ $<

lttng-ust-provider-hello.a: lttng-ust-provider-hello.o
	ar -rc $@ lttng-ust-provider-hello.o

hello.o: hello.c
	$(CC) $(CPPFLAGS) $(LOCAL_CPPFLAGS) $(CFLAGS) $(AM_CPPFLAGS) \
		$(AM_CFLAGS) -c -o $@ $<

hello: hello.o lttng-ust-provider-hello.a
	$(CC) -o $@ $(LDFLAGS) $(CPPFLAGS) $(AM_LDFLAGS) $(AM_CFLAGS) \
		hello.o lttng-ust-provider-hello.a $(LIBS)

.PHONY: clean
clean:
	rm -f *.o *.a hello
