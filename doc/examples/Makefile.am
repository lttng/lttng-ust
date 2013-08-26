doc_examplesdir = ${docdir}/examples
doc_examples_easy_ustdir = ${docdir}/examples/easy-ust
doc_examples_gen_tpdir = ${docdir}/examples/gen-tp
doc_examples_demodir = ${docdir}/examples/demo
doc_examples_hello_static_libdir = ${docdir}/examples/hello-static-lib

dist_doc_examples_DATA = README

dist_doc_examples_easy_ust_DATA = easy-ust/Makefile \
	easy-ust/sample.c \
	easy-ust/sample_component_provider.h easy-ust/tp.c

dist_doc_examples_gen_tp_DATA = gen-tp/Makefile \
	gen-tp/sample.c  gen-tp/sample_tracepoint.tp

dist_doc_examples_demo_DATA = demo/demo.c \
	demo/demo-trace \
	demo/Makefile \
	demo/README \
	demo/tp2.c \
	demo/tp3.c \
	demo/tp.c \
	demo/ust_tests_demo2.h \
	demo/ust_tests_demo3.h \
	demo/ust_tests_demo.h

dist_doc_examples_hello_static_lib_DATA = hello-static-lib/Makefile \
	hello-static-lib/hello.c \
	hello-static-lib/README \
	hello-static-lib/ust_tests_hello.h \
	hello-static-lib/tp.c

if NO_SHARED
# Don't build examples if shared libraries support was explicitly
# disabled.
else
# Copies are for VPATH build support
SUBDIRS_PROXY = easy-ust demo gen-tp hello-static-lib

all-local:
	@if [ x"$(srcdir)" != x"$(builddir)" ]; then \
		cp -f $(srcdir)/Makefile.examples.template $(builddir); \
		for subdir in $(SUBDIRS_PROXY); do \
			cp -fR $(srcdir)/$$subdir $(builddir); \
		done; \
	fi
	for subdir in $(SUBDIRS_PROXY); do \
		cd $$subdir && $(MAKE) AM_CPPFLAGS="$(CPPFLAGS) -I../../../include/" AM_CFLAGS='$(CFLAGS)' AM_LDFLAGS='$(LDFLAGS) -L../../../liblttng-ust/.libs/ -Wl,-rpath="$(PWD)/../../liblttng-ust/.libs/"' LTTNG_GEN_TP_PATH="../../../tools/" $(AM_MAKEFLAGS) all; cd ..; \
	done

clean-local:
	for subdir in $(SUBDIRS_PROXY); do \
		cd $$subdir && $(MAKE) $(AM_MAKEFLAGS) clean; cd ..; \
	done
	@if [ x"$(srcdir)" != x"$(builddir)" ]; then \
		for subdir in $(SUBDIRS_PROXY); do \
			rm -rf $(builddir)/$$subdir; \
		done; \
		rm -f $(builddir)/Makefile.examples.template; \
	fi
endif
