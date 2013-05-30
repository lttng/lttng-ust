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

# This makefile is not using automake so that users can see how to build
# a program with a statically embedded tracepoint provider probe.
# the "html" target helps for documentation (req. code2html)

CC = gcc
LIBS = -ldl -llttng-ust		# On Linux
#LIBS = -lc -llttng-ust		# On BSD
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
	dvi pdf ps info tags ctags
.PHONY: $(EMPTY_AUTOMAKE_TARGETS)
$(EMPTY_AUTOMAKE_TARGETS):
endif

all: sample

sample: sample.o tp.o
	$(CC) -o $@ $^ $(LDFLAGS) $(LIBS)

sample.o: sample.c sample_component_provider.h
	$(CC) $(CPPFLAGS) $(LOCAL_CPPFLAGS) $(CFLAGS) -c -o $@ $<

tp.o: tp.c sample_component_provider.h
	$(CC) $(CPPFLAGS) $(LOCAL_CPPFLAGS) $(CFLAGS) -c -o $@ $<

html: sample_component_provider.html sample.html tp.html

%.html: %.c
	code2html -lc $< $@

%.html : %.h
	code2html -lc $< $@

.PHONY: clean
clean:
	rm -f *.html
	rm -f *.o sample
