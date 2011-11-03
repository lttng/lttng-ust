if BUILD_JNI_INTERFACE

AM_CPPFLAGS = -I$(top_srcdir)/include

lib_LTLIBRARIES = liblttng-ust-java.la
liblttng_ust_java_la_SOURCES = UST.c UST.h ust_java.h
dist_noinst_DATA = UST.java
liblttng_ust_java_la_LIBADD = -lc -L$(top_builddir)/liblttng-ust/.libs -llttng-ust

all: UST.class UST.h

clean-local:
	rm -rf UST.h UST.class

UST.class: UST.java
	javac -d "$(builddir)" "$(srcdir)/UST.java"

UST.h: UST.class
	javah -jni UST

endif
