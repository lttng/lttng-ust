# SPDX-License-Identifier: MIT
#
# Copyright (C) 2013 Jérémie Galarneau <jeremie.galarneau@efficios.com>
# Copyright (C) 2014 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
#
# This Makefile is not using automake so that users may see how to build
# a program with tracepoint provider probes as stand-alone shared objects.
#
# This makefile is purposefully kept simple to support GNU and BSD make.

LIBS = -ldl -llttng-ust	# On Linux
#LIBS = -lc	# On BSD
LOCAL_CPPFLAGS += -I.
AM_V_P := :

all: demo-tracelog demo-vtracelog

demo-tracelog.o: demo-tracelog.c
	@if $(AM_V_P); then set -x; else echo "  CC       $@"; fi; \
		$(CC) $(CPPFLAGS) $(LOCAL_CPPFLAGS) $(AM_CFLAGS) $(AM_CPPFLAGS) \
		$(CFLAGS) -c -o $@ $<

demo-tracelog: demo-tracelog.o
	@if $(AM_V_P); then set -x; else echo "  CCLD     $@"; fi; \
		$(CC) $(LDFLAGS) $(AM_CFLAGS) $(AM_LDFLAGS) $(CFLAGS) \
		-o $@ $< $(LIBS)

demo-vtracelog.o: demo-vtracelog.c
	@if $(AM_V_P); then set -x; else echo "  CC       $@"; fi; \
		$(CC) $(CPPFLAGS) $(LOCAL_CPPFLAGS) $(AM_CFLAGS) $(AM_CPPFLAGS) \
		$(CFLAGS) -c -o $@ $<

demo-vtracelog: demo-vtracelog.o
	@if $(AM_V_P); then set -x; else echo "  CCLD     $@"; fi; \
		$(CC) $(LDFLAGS) $(AM_CFLAGS) $(AM_LDFLAGS) $(CFLAGS) \
		-o $@ $< $(LIBS)

.PHONY: clean
clean:
	rm -f *.o *.a demo-tracelog demo-vtracelog
