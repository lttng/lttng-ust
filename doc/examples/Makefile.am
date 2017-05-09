doc_examplesdir = ${docdir}/examples
doc_examples_easy_ustdir = ${docdir}/examples/easy-ust
doc_examples_gen_tpdir = ${docdir}/examples/gen-tp
doc_examples_demodir = ${docdir}/examples/demo
doc_examples_hello_static_libdir = ${docdir}/examples/hello-static-lib
doc_examples_demo_tracefdir = ${docdir}/examples/demo-tracef
doc_examples_demo_tracelogdir = ${docdir}/examples/demo-tracelog
doc_examples_clock_overridedir = ${docdir}/examples/clock-override
doc_examples_getcpu_overridedir = ${docdir}/examples/getcpu-override
doc_examples_cmakedir = ${docdir}/examples/cmake-multiple-shared-libraries

if BUILD_JAVA_AGENT_WITH_JUL
doc_examples_java_juldir = ${docdir}/examples/java-jul
dist_doc_examples_java_jul_DATA = java-jul/Makefile \
				  java-jul/Hello.java \
				  java-jul/run \
				  java-jul/ApplicationContextExample.java \
				  java-jul/FilterChangeListenerExample.java \
				  java-jul/README
SUBDIRS_JUL = java-jul
endif

if BUILD_JAVA_AGENT_WITH_LOG4J
doc_examples_java_log4jdir = ${docdir}/examples/java-log4j
dist_doc_examples_java_log4j_DATA = java-log4j/Makefile \
				  java-log4j/Hello.java \
				  java-log4j/run
SUBDIRS_LOG4J = java-log4j
endif

if BUILD_PYTHON_AGENT
doc_examples_pythondir = ${docdir}/examples/python
dist_doc_examples_python_DATA = python/hello.py
endif

if HAVE_CMAKE
if CXX_WORKS
SUBDIRS_CMAKE = cmake-multiple-shared-libraries
endif
endif

dist_doc_examples_DATA = README

dist_doc_examples_easy_ust_DATA = easy-ust/Makefile \
	easy-ust/sample.c \
	easy-ust/sample_component_provider.h easy-ust/tp.c

dist_doc_examples_cmake_DATA = \
  cmake-multiple-shared-libraries/CMakeLists.txt \
  cmake-multiple-shared-libraries/cmake/FindLTTngUST.cmake \
  cmake-multiple-shared-libraries/aligner.cpp \
  cmake-multiple-shared-libraries/aligner-lib.cpp \
  cmake-multiple-shared-libraries/aligner-lib.h \
  cmake-multiple-shared-libraries/README.md \
  cmake-multiple-shared-libraries/tester.cpp \
  cmake-multiple-shared-libraries/tester-lib.cpp \
  cmake-multiple-shared-libraries/tester-lib.h \
  cmake-multiple-shared-libraries/tracepoint-provider.cpp \
  cmake-multiple-shared-libraries/tracepoint-provider.h \
  cmake-multiple-shared-libraries/trace.sh

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

dist_doc_examples_demo_tracef_DATA = demo-tracef/Makefile \
	demo-tracef/demo-tracef.c \
	demo-tracef/README

dist_doc_examples_demo_tracelog_DATA = demo-tracelog/Makefile \
	demo-tracelog/demo-tracelog.c \
	demo-tracelog/README

dist_doc_examples_clock_override_DATA = clock-override/Makefile \
	clock-override/lttng-ust-clock-override-example.c \
	clock-override/run-clock-override \
	clock-override/README

dist_doc_examples_getcpu_override_DATA = getcpu-override/Makefile \
	getcpu-override/lttng-ust-getcpu-override-example.c \
	getcpu-override/run-getcpu-override \
	getcpu-override/README

# Copies are for VPATH build support
SUBDIRS_PROXY = easy-ust demo hello-static-lib demo-tracef clock-override \
		getcpu-override demo-tracelog

if BUILD_GEN_TP_EXAMPLES
SUBDIRS_PROXY += gen-tp
endif

all-local:
	@if [ x"$(srcdir)" != x"$(builddir)" ]; then \
		for subdir in $(SUBDIRS_PROXY) $(SUBDIRS_JUL) $(SUBDIRS_LOG4J) $(SUBDIRS_CMAKE); do \
			cp -pfR $(srcdir)/$$subdir $(builddir); \
			chmod -R u+w $(builddir)/$$subdir; \
		done; \
	fi; \
	if [ x"$(shell echo "$(top_srcdir)" | grep "^/" | wc -l)" = x"1" ]; then \
		echo "Examples: absolute top_srcdir path $(top_srcdir)"; \
		rel_src_subdir=""; \
	else \
		echo "Examples: relative top_srcdir path $(top_srcdir)"; \
		rel_src_subdir="../"; \
	fi; \
	if [ x"$(shell echo "$(top_builddir)" | grep "^/" | wc -l)" = x"1" ]; then \
		echo "Examples: absolute top_builddir path $(top_builddir)"; \
		rel_build_subdir=""; \
	else \
		echo "Examples: relative top_builddir path $(top_builddir)"; \
		rel_build_subdir="../"; \
	fi; \
	for subdir in $(SUBDIRS_PROXY); do \
		(cd $$subdir && $(MAKE) CC="$(CC)" CPPFLAGS="$(CPPFLAGS)" AM_CPPFLAGS="$(AM_CPPFLAGS) -I$$rel_src_subdir$(top_srcdir)/include/ -I$$rel_build_subdir$(top_builddir)/include/" CFLAGS='$(CFLAGS)' AM_CFLAGS='$(AM_CFLAGS)' LDFLAGS="$(LDFLAGS)" AM_LDFLAGS='$(AM_LDFLAGS) -L../../../liblttng-ust/.libs -Wl,-rpath="$(PWD)/../../liblttng-ust/.libs/" -Wl,-rpath-link="$(PWD)/../../liblttng-ust/.libs/"' LTTNG_GEN_TP_PATH="../../../tools/" $(AM_MAKEFLAGS) all && cd ..) || exit 1; \
	done; \
	if [ x"$(SUBDIRS_JUL)" != x"" ]; then \
		for subdir in $(SUBDIRS_JUL); do \
			(cd $$subdir && $(MAKE) JAVA_CLASSPATH_OVERRIDE_JUL="../../../liblttng-ust-java-agent/java/lttng-ust-agent-jul" JAVA_CLASSPATH_OVERRIDE_COMMON="../../../liblttng-ust-java-agent/java/lttng-ust-agent-common" $(AM_MAKEFLAGS) all && cd ..) || exit 1; \
		done; \
	fi; \
	if [ x"$(SUBDIRS_LOG4J)" != x"" ]; then \
		for subdir in $(SUBDIRS_LOG4J); do \
			(cd $$subdir && $(MAKE) JAVA_CLASSPATH_OVERRIDE_LOG4J="../../../liblttng-ust-java-agent/java/lttng-ust-agent-log4j" JAVA_CLASSPATH_OVERRIDE_COMMON="../../../liblttng-ust-java-agent/java/lttng-ust-agent-common" $(AM_MAKEFLAGS) all && cd ..) || exit 1; \
		done; \
	fi; \
	if [ x"$(SUBDIRS_CMAKE)" != x"" ]; then \
		for subdir in $(SUBDIRS_CMAKE); do \
			( \
				cd $$subdir && \
				$(MKDIR_P) build && \
				cd build && \
				CC="$(CC)" \
				CXX="$(CXX)" \
				cmake \
				-DCMAKE_INCLUDE_PATH="$(abs_top_srcdir)/include;$(abs_top_builddir)/include" \
				-DCMAKE_LIBRARY_PATH="$(abs_top_builddir)/liblttng-ust/.libs" \
				-DCMAKE_C_FLAGS="$(AM_CFLAGS) $(AM_CPPFLAGS) $(CPPFLAGS) $(CFLAGS)" \
				-DCMAKE_CXX_FLAGS="$(AM_CXXFLAGS) $(AM_CPPFLAGS) $(CXXFLAGS) $(CPPFLAGS)" \
				-DCMAKE_EXE_LINKER_FLAGS="$(AM_LDFLAGS) $(LDFLAGS)" \
				.. && \
				$(MAKE) && \
				cd .. \
			) || exit 1; \
		done; \
	fi;


clean-local:
	@for subdir in $(SUBDIRS_PROXY); do \
		if [ -d $$subdir ]; then \
			(cd $$subdir && $(MAKE) $(AM_MAKEFLAGS) clean && cd ..) || exit 1; \
		fi; \
	done; \
	if [ x"$(SUBDIRS_JUL)" != x"" ]; then \
		for subdir in $(SUBDIRS_JUL); do \
			if [ -d $$subdir ]; then \
				(cd $$subdir && $(MAKE) $(AM_MAKEFLAGS) clean && cd ..) || exit 1; \
			fi; \
		done; \
	fi; \
	if [ x"$(SUBDIRS_LOG4J)" != x"" ]; then \
		for subdir in $(SUBDIRS_LOG4J); do \
			if [ -d $$subdir ]; then \
				(cd $$subdir && $(MAKE) $(AM_MAKEFLAGS) clean && cd ..) || exit 1; \
			fi; \
		done; \
	fi; \
	if [ x"$(SUBDIRS_CMAKE)" != x"" ]; then \
		for subdir in $(SUBDIRS_CMAKE); do \
			if [ -d $$subdir ]; then \
				(cd $$subdir && rm -rf build && cd ..) || exit 1; \
			fi; \
		done; \
	fi; \
	if [ x"$(srcdir)" != x"$(builddir)" ]; then \
		for subdir in $(SUBDIRS_PROXY) $(SUBDIRS_JUL) $(SUBDIRS_LOG4J) $(SUBDIRS_CMAKE); do \
			rm -rf $(builddir)/$$subdir; \
		done; \
	fi;
