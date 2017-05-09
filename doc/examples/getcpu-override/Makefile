# Copyright (C) 2013  Jérémie Galarneau <jeremie.galarneau@efficios.com>
# Copyright (C) 2014  Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
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

all: lttng-ust-getcpu-override-example.so

lttng-ust-getcpu-override-example.o: lttng-ust-getcpu-override-example.c
	$(CC) $(CPPFLAGS) $(LOCAL_CPPFLAGS) $(AM_CFLAGS) $(AM_CPPFLAGS) \
		$(CFLAGS) -fpic -c -o $@ $<

lttng-ust-getcpu-override-example.so: lttng-ust-getcpu-override-example.o
	$(CC) -shared -Wl,--no-as-needed -o $@ $(LDFLAGS) $(AM_CFLAGS) \
		$(AM_LDFLAGS) $(CFLAGS) lttng-ust-getcpu-override-example.o

.PHONY: clean
clean:
	rm -f *.o *.so
