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
# a program with tracepoint provider probes as stand-alone shared objects.
#
# This makefile is purposefully kept simple to support GNU and BSD make.

LIBS = -ldl	# On Linux
#LIBS = -lc	# On BSD
LOCAL_CPPFLAGS += -I.

all: demo lttng-ust-provider-ust-tests-demo.so lttng-ust-provider-ust-tests-demo3.so

tp.o: tp.c ust_tests_demo.h
	$(CC) $(CPPFLAGS) $(LOCAL_CPPFLAGS) $(AM_CFLAGS) $(AM_CPPFLAGS) \
		$(CFLAGS) -fpic -c -o $@ $<

tp2.o: tp2.c ust_tests_demo2.h
	$(CC) $(CPPFLAGS) $(LOCAL_CPPFLAGS) $(AM_CFLAGS) $(AM_CPPFLAGS) \
		$(CFLAGS) -fpic -c -o $@ $<

lttng-ust-provider-ust-tests-demo.so: tp.o tp2.o
	$(CC) -shared -Wl,--no-as-needed -o $@ $(LDFLAGS) $(AM_CFLAGS) \
		$(AM_LDFLAGS) $(CFLAGS) -llttng-ust tp.o tp2.o

tp3.o: tp3.c ust_tests_demo3.h
	$(CC) $(CPPFLAGS) $(LOCAL_CPPFLAGS) $(AM_CFLAGS) $(AM_CPPFLAGS) \
		$(CFLAGS) -fpic -c -o $@ $<

lttng-ust-provider-ust-tests-demo3.so: tp3.o
	$(CC) -shared -Wl,--no-as-needed -o $@ $(LDFLAGS) $(AM_CFLAGS) \
		$(AM_LDFLAGS) $(CFLAGS) -llttng-ust tp3.o

demo.o: demo.c
	$(CC) $(CPPFLAGS) $(LOCAL_CPPFLAGS) $(AM_CFLAGS) $(AM_CPPFLAGS) \
		$(CFLAGS) -c -o $@ $<

demo: demo.o
	$(CC) $(LDFLAGS) $(AM_CFLAGS) $(AM_LDFLAGS) $(CFLAGS) \
		-o $@ demo.o $(LIBS)

.PHONY: clean
clean:
	rm -f *.o *.so demo
