AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_builddir)/include -Wsystem-headers

noinst_PROGRAMS = hello
hello_SOURCES = hello.cpp tp-cpp.cpp ust_tests_hello.h
hello_LDADD = $(top_builddir)/liblttng-ust/liblttng-ust.la $(DL_LIBS)
