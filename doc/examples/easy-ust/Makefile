# SPDX-License-Identifier: MIT
#
# Copyright (C) 2011-2012 Matthew Khouzam <matthew.khouzam@ericsson.com>
# Copyright (C) 2012 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
#
# This makefile is not using automake so that users can see how to build
# a program with a statically embedded tracepoint provider probe.
# the "html" target helps for documentation (req. code2html)
#
# This makefile is purposefully kept simple to support GNU and BSD make.

LIBS = -ldl -llttng-ust		# On Linux
#LIBS = -lc -llttng-ust		# On BSD
LOCAL_CPPFLAGS += -I.
AM_V_P := :

all: sample

sample: sample.o tp.o
	@if $(AM_V_P); then set -x; else echo "  CCLD     $@"; fi; \
		$(CC) -o $@ $(LDFLAGS) $(AM_CFLAGS) $(AM_LDFLAGS) $(CFLAGS) \
		sample.o tp.o $(LIBS)

sample.o: sample.c sample_component_provider.h
	@if $(AM_V_P); then set -x; else echo "  CC       $@"; fi; \
		$(CC) $(CPPFLAGS) $(LOCAL_CPPFLAGS) $(AM_CFLAGS) $(AM_CPPFLAGS) \
		$(CFLAGS) -c -o $@ $<

tp.o: tp.c sample_component_provider.h
	@if $(AM_V_P); then set -x; else echo "  CC       $@"; fi; \
		$(CC) $(CPPFLAGS) $(LOCAL_CPPFLAGS) $(AM_CFLAGS) $(AM_CPPFLAGS) \
		$(CFLAGS) -c -o $@ $<

html: sample_component_provider.html sample.html tp.html

%.html: %.c
	code2html -lc $< $@

%.html : %.h
	code2html -lc $< $@

.PHONY: clean
clean:
	rm -f *.html
	rm -f *.o sample
