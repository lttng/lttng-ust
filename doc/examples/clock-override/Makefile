# SPDX-License-Identifier: MIT
#
# Copyright (C) 2013  Jérémie Galarneau <jeremie.galarneau@efficios.com>
# Copyright (C) 2014  Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
#
# This Makefile is not using automake so that users may see how to build
# a program with tracepoint provider probes as stand-alone shared objects.
#
# This makefile is purposefully kept simple to support GNU and BSD make.

LIBS = -ldl	# On Linux
#LIBS = -lc	# On BSD
LOCAL_CPPFLAGS += -I.
AM_V_P := :

all: lttng-ust-clock-override-example.so

lttng-ust-clock-override-example.o: lttng-ust-clock-override-example.c
	@if $(AM_V_P); then set -x; else echo "  CC       $@"; fi; \
		$(CC) $(CPPFLAGS) $(LOCAL_CPPFLAGS) $(AM_CFLAGS) $(AM_CPPFLAGS) \
		$(CFLAGS) -fpic -c -o $@ $<

lttng-ust-clock-override-example.so: lttng-ust-clock-override-example.o
	@if $(AM_V_P); then set -x; else echo "  CCLD     $@"; fi; \
		$(CC) -Wl,--no-as-needed -o $@ $(LDFLAGS) $(AM_CFLAGS) \
		$(AM_LDFLAGS) $(CFLAGS) -shared -fpic lttng-ust-clock-override-example.o

.PHONY: clean
clean:
	rm -f *.o *.so
