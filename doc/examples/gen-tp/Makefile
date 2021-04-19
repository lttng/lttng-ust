# SPDX-License-Identifier: MIT
#
# Copyright (C) 2011-2012  Matthew Khouzam <matthew.khouzam@ericsson.com>
# Copyright (C) 2012  Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
# Copyright (C) 2012  Yannick Brosseau <yannick.brosseau@gmail.com>
#
# This makefile is not using automake so that people can see how to make
# simply. It builds a program with a statically embedded tracepoint
# provider probe.
#
# This makefile is purposefully kept simple to support GNU and BSD make.

PYTHON := python

LIBS = -ldl -llttng-ust		#On Linux
#LIBS = -lc -llttng-ust		#On BSD
AM_V_P := :

all: sample

sample: sample.o sample_tracepoint.o
	@if $(AM_V_P); then set -x; else echo "  CCLD     $@"; fi; \
		$(CC) $(LDFLAGS) $(AM_CFLAGS) $(AM_LDFLAGS) $(CFLAGS) \
		-o $@ sample.o sample_tracepoint.o $(LIBS)

sample.o: sample.c sample_tracepoint.h
	@if $(AM_V_P); then set -x; else echo "  CC       $@"; fi; \
		$(CC) $(CPPFLAGS) $(AM_CFLAGS) $(AM_CPPFLAGS) $(CFLAGS) \
		-c -o $@ $<

# Use this command to compile the .c manually
#sample_tracepoint.o: sample_tracepoint.c sample_tracepoint.h
#	$(CC) $(CPPFLAGS) $(AM_CFLAGS) $(AM_CPPFLAGS) $(CFLAGS) \
#		-I. -c -o $@ $<

# This rule generate .o only and depends on rules for generating
# the .h and .c
%.o: %.tp %.c %.h
	@if $(AM_V_P); then set -x; else echo "  CC       $@"; fi; \
		CPPFLAGS="$(AM_CPPFLAGS) $(CPPFLAGS)" \
		CFLAGS="$(AM_CFLAGS) $(CFLAGS)" \
		CC="$(CC)" \
		$(PYTHON) $(LTTNG_GEN_TP_PATH)lttng-gen-tp -o $@ $<

# The following rule can be used to generate all files instead of having one
# for each file type. Note that the sample.o has a dependency on the
# .h, so you need to change that if you remove the %.h rule.
#%.o: %.tp
#	lttng-gen-tp $<

%.h: %.tp
	@if $(AM_V_P); then set -x; else echo "  GEN      $@"; fi; \
		$(PYTHON) $(LTTNG_GEN_TP_PATH)lttng-gen-tp -o $@ $<

%.c: %.tp
	@if $(AM_V_P); then set -x; else echo "  GEN      $@"; fi; \
		$(PYTHON)  $(LTTNG_GEN_TP_PATH)lttng-gen-tp -o $@ $<

.PHONY: clean
clean:
	rm -f *.o sample
	rm -f sample_tracepoint.h sample_tracepoint.c
