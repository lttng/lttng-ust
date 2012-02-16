# Copyright (C) 2011-2012  Matthew Khouzam <matthew.khouzam@ericsson.com>
# Copyright (C) 2012  Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
# Copyright (C) 2012  Yannick Brosseau <yannick.brosseau@gmail.com>
#
# THIS MATERIAL IS PROVIDED AS IS, WITH ABSOLUTELY NO WARRANTY EXPRESSED
# OR IMPLIED.  ANY USE IS AT YOUR OWN RISK.
#
# Permission is hereby granted to use or copy this program for any
# purpose,  provided the above notices are retained on all copies.
# Permission to modify the code and to distribute modified code is
# granted, provided the above notices are retained, and a notice that
# the code was modified is included with the above copyright notice.

# This makefile is not using automake so that people can see how to make
# simply. It builds a program with a statically embedded tracepoint
# provider probe.

CC = gcc
LIBS = -ldl -llttng-ust

all: sample

sample: sample.o sample-tp.o
	$(CC) $(LIBS) -o $@ $^

sample.o: sample.c sample_tracepoint.h
	$(CC) $(CFLAGS) -c -o $@ $<

sample-tp.o: sample_tracepoint.c sample_tracepoint.h
	$(CC) $(CFLAGS) -I. -c -o $@ $<

%.h: %.tp
	lttng-gen-tp -o $@ $<
%.c: %.tp
	lttng-gen-tp -o $@ $<

.PHONY: clean
clean:
	rm -f *.o sample
	rm -f sample_tracepoint.h sample_tracepoint.c
