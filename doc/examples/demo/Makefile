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

# This Makefile is not using automake so that people may see how to build
# a program and tracepoint provider probes as stand-alone shared objects.

CC = gcc
LIBS = -ldl	# On Linux
#LIBS = -lc	# On BSD
CFLAGS = -I.

all: demo lttng-ust-provider-ust-tests-demo.so lttng-ust-provider-ust-tests-demo3.so

lttng-ust-provider-ust-tests-demo.o: tp.c tp2.c ust_tests_demo.h ust_tests_demo2.h
	$(CC) $(CFLAGS) -fpic -c -o $@ $<

lttng-ust-provider-ust-tests-demo.so: lttng-ust-provider-ust-tests-demo.o
	$(CC) -shared -o $@ -llttng-ust $<

lttng-ust-provider-ust-tests-demo3.o: tp3.c ust_tests_demo3.h
	$(CC) $(CFLAGS) -fpic -c -o $@ $<

lttng-ust-provider-ust-tests-demo3.so: lttng-ust-provider-ust-tests-demo3.o
	$(CC) -shared -o $@ -llttng-ust $<

demo.o: demo.c
	$(CC) $(CFLAGS) -c -o $@ $<

demo: demo.o
	$(CC) demo.o -o $@ $(LIBS)

.PHONY: clean
clean:
	rm -f *.o *.so demo
