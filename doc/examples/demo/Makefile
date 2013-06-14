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

# This Makefile is not using automake so that users may see how to build
# a program with tracepoint provider probes as stand-alone shared objects.

CC = gcc
LIBS = -ldl	# On Linux
#LIBS = -lc	# On BSD
LOCAL_CPPFLAGS += -I.

# Only necessary when building from the source tree and lttng-ust is not
# installed
ifdef BUILD_EXAMPLES_FROM_TREE
LOCAL_CPPFLAGS += -I../../../include/
LIBLTTNG_UST_PATH = ../../../liblttng-ust/.libs/
override LDFLAGS += -L$(LIBLTTNG_UST_PATH) -Wl,-rpath='$$ORIGIN/$(LIBLTTNG_UST_PATH)'

# Third-party Makefiles have to define these targets to integrate with an
# automake project
EMPTY_AUTOMAKE_TARGETS = distdir install install-data install-exec uninstall \
	install-dvi install-html install-info install-ps install-pdf \
	installdirs check installcheck mostlyclean distclean maintainer-clean \
	dvi html pdf ps info tags ctags
.PHONY: $(EMPTY_AUTOMAKE_TARGETS)
$(EMPTY_AUTOMAKE_TARGETS):
endif

all: demo lttng-ust-provider-ust-tests-demo.so lttng-ust-provider-ust-tests-demo3.so

tp.o: tp.c ust_tests_demo.h
	$(CC) $(CPPFLAGS) $(LOCAL_CPPFLAGS) $(CFLAGS) -fpic -c -o $@ $<

tp2.o: tp2.c ust_tests_demo2.h
	$(CC) $(CPPFLAGS) $(LOCAL_CPPFLAGS) $(CFLAGS) -fpic -c -o $@ $<

lttng-ust-provider-ust-tests-demo.so: tp.o tp2.o
	$(CC) -shared -Wl,--no-as-needed -o $@ $(LDFLAGS) -llttng-ust $^

tp3.o: tp3.c ust_tests_demo3.h
	$(CC) $(CPPFLAGS) $(LOCAL_CPPFLAGS) $(CFLAGS) -fpic -c -o $@ $<

lttng-ust-provider-ust-tests-demo3.so: tp3.o
	$(CC) -shared -Wl,--no-as-needed -o $@ $(LDFLAGS) -llttng-ust $^

demo.o: demo.c
	$(CC) $(CPPFLAGS) $(LOCAL_CPPFLAGS) $(CFLAGS) -c -o $@ $<

demo: demo.o
	$(CC) -o $@ $^ $(LIBS)

.PHONY: clean
clean:
	rm -f *.o *.so demo
