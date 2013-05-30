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
# a program with tracepoint provider probes compiled as static libraries.

CC = gcc
LOCAL_CPPFLAGS += -I.
LIBS = -ldl -llttng-ust	# On Linux
#LIBS = -lc -llttng-ust	# On BSD

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

all: hello

lttng-ust-provider-hello.o: tp.c ust_tests_hello.h
	$(CC) $(CPPFLAGS) $(LOCAL_CPPFLAGS) $(CFLAGS) -c -o $@ $<

lttng-ust-provider-hello.a: lttng-ust-provider-hello.o
	ar -rc $@ $^

hello.o: hello.c
	$(CC) $(CPPFLAGS) $(LOCAL_CPPFLAGS) $(CFLAGS) -c -o $@ $<

hello: hello.o lttng-ust-provider-hello.a
	$(CC) -o $@ $(LDFLAGS) $^ $(LIBS)

.PHONY: clean
clean:
	rm -f *.o *.a hello
