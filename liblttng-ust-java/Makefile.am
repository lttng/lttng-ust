if BUILD_JNI_INTERFACE

AM_CPPFLAGS = -I$(top_srcdir)/include

lib_LTLIBRARIES = liblttng-ust-java.la
liblttng_ust_java_la_SOURCES = LTTngUst.c org_lttng_ust_LTTngUst.h lttng_ust_java.h
dist_noinst_DATA = LTTngUst.java
liblttng_ust_java_la_LIBADD = -lc -L$(top_builddir)/liblttng-ust/.libs -llttng-ust

all: LTTngUst.class org_lttng_ust_LTTngUst.h

clean-local:
	rm  org_lttng_ust_LTTngUst.h
	rm -rf org/

LTTngUst.class: LTTngUst.java
	javac -d "$(builddir)" "$(srcdir)/LTTngUst.java"

org_lttng_ust_LTTngUst.h: LTTngUst.class
	javah org.lttng.ust.LTTngUst

endif
