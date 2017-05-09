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

liblttng_ust_java_la_LIBADD = -lc -L$(top_builddir)/liblttng-ust/.libs -llttng-ust

$(jarfile): classnoinst.stamp
	$(JAR) cf $(JARFLAGS) $@ $(pkgpath)/*.class

org_lttng_ust_LTTngUst.h: jni-header.stamp

jni-header.stamp: $(dist_noinst_JAVA)
	$(JAVAH) -classpath $(srcdir) $(JAVAHFLAGS) org.lttng.ust.LTTngUst && \
	echo "JNI header generated" > jni-header.stamp

all-local: org_lttng_ust_LTTngUst.h

CLEANFILES = $(jarfile) $(pkgpath)/*.class jni-header.stamp org_lttng_ust_LTTngUst.h
