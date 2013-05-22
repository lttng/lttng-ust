if BUILD_JNI_INTERFACE

AM_CPPFLAGS = -I$(top_srcdir)/include

lib_LTLIBRARIES = liblttng-ust-java.la
liblttng_ust_java_la_SOURCES = LTTngUst.c lttng_ust_java.h
nodist_liblttng_ust_java_la_SOURCES = org_lttng_ust_LTTngUst.h
dist_noinst_DATA = LTTngUst.java
liblttng_ust_java_la_LIBADD = -lc -L$(top_builddir)/liblttng-ust/.libs -llttng-ust

all: LTTngUst.class org_lttng_ust_LTTngUst.h liblttng-ust-java.jar

clean-local:
	rm -f org_lttng_ust_LTTngUst.h
	rm -f liblttng-ust-java.jar
	rm -rf org/

LTTngUst.c: org_lttng_ust_LTTngUst.h

LTTngUst.class: LTTngUst.java
	javac -d "$(builddir)" "$(srcdir)/LTTngUst.java"

org_lttng_ust_LTTngUst.h: LTTngUst.class
	javah org.lttng.ust.LTTngUst

liblttng-ust-java.jar: LTTngUst.class
	jar cf liblttng-ust-java.jar org/*

endif
