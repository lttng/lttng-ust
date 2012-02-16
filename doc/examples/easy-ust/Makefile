# Copyright (C) 2011-2012  Matthew Khouzam <matthew.khouzam@ericsson.com> 
# Copyright (C) 2012  Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
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
# the "html" target helps for documentation (req. code2html)

CC = gcc
LIBS = -ldl -llttng-ust
CFLAGS = -I.

all: sample

sample: sample.o tp.o
	$(CC) $(LIBS) -o $@ $^

sample.o: sample.c sample_component_provider.h
	$(CC) $(CFLAGS) -c -o $@ $<

tp.o: tp.c sample_component_provider.h
	$(CC) $(CFLAGS) -c -o $@ $<

html: sample_component_provider.html sample.html tp.html

%.html: %.c 
	code2html -lc $< $@

%.html : %.h
	code2html -lc $< $@

.PHONY: clean
clean:
	rm -f *.html  
	rm -f *.o sample
