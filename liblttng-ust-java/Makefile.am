JAVAROOT = .
jarfile = liblttng-ust-java.jar
jardir = $(datadir)/java
pkgpath = org/lttng/ust

dist_noinst_JAVA = $(pkgpath)/LTTngUst.java
jar_DATA = $(jarfile)
BUILT_SOURCES = org_lttng_ust_LTTngUst.h

AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_builddir)/include $(JNI_CPPFLAGS)
lib_LTLIBRARIES = liblttng-ust-java.la
liblttng_ust_java_la_SOURCES = LTTngUst.c lttng_ust_java.h
nodist_liblttng_ust_java_la_SOURCES = org_lttng_ust_LTTngUst.h

liblttng_ust_java_la_LIBADD = -lc \
	$(top_builddir)/liblttng-ust/liblttng-ust.la

$(jarfile): classnoinst.stamp
	$(JAR) cf $(JARFLAGS) $@ $(pkgpath)/*.class

if !HAVE_JAVAH
# If we don't have javah, assume we are running openjdk >= 10 and use javac
# to generate the jni header file.
AM_JAVACFLAGS = -h .

org_lttng_ust_LTTngUst.h: $(jarfile)
else
org_lttng_ust_LTTngUst.h: jni-header.stamp

jni-header.stamp: $(dist_noinst_JAVA)
	$(JAVAH) -classpath $(srcdir) $(JAVAHFLAGS) org.lttng.ust.LTTngUst && \
	echo "JNI header generated" > jni-header.stamp
endif

all-local: org_lttng_ust_LTTngUst.h

EXTRA_DIST = README

CLEANFILES = $(jarfile) $(pkgpath)/*.class jni-header.stamp org_lttng_ust_LTTngUst.h
