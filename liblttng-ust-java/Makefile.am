if BUILD_JNI_INTERFACE

AM_CPPFLAGS = -I$(top_srcdir)/include

lib_LTLIBRARIES = liblttng-ust-java.la
liblttng_ust_java_la_SOURCES = LTTNG_UST.c LTTNG_UST.h lttng_ust_java.h
dist_noinst_DATA = LTTNG_UST.java
liblttng_ust_java_la_LIBADD = -lc -L$(top_builddir)/liblttng-ust/.libs -llttng-ust

all: LTTNG_UST.class LTTNG_UST.h

clean-local:
	rm -rf LTTNG_UST.h LTTNG_UST.class

LTTNG_UST.class: LTTNG_UST.java
	javac -d "$(builddir)" "$(srcdir)/LTTNG_UST.java"

LTTNG_UST.h: LTTNG_UST.class
	javah -classpath ./ -jni LTTNG_UST

endif
