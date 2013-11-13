if BUILD_JNI_INTERFACE

AM_CPPFLAGS = -I$(top_srcdir)/include

lib_LTLIBRARIES = liblttng-ust-jul-jni.la
liblttng_ust_jul_jni_la_SOURCES = LTTngUst.c lttng_ust_jul.h
nodist_liblttng_ust_jul_jni_la_SOURCES = org_lttng_ust_jul_LTTngUst.h
dist_noinst_DATA = $(LTTNG_JUL_SRCDIR)/LTTngUst.java
liblttng_ust_jul_jni_la_LIBADD = -lc -L$(top_builddir)/liblttng-ust/.libs -llttng-ust

LTTNG_JUL_SRCDIR = $(srcdir)/org/lttng/ust/jul
LTTNG_JUL_DESTDIR = $(builddir)/org/lttng/ust/jul

if HAVE_JAVA_JDK
JCC=$(JAVA_JDK)/bin
else
JCC=javac
endif

all-local: $(LTTNG_JUL_DESTDIR)/LTTngAgent.class $(LTTNG_JUL_DESTDIR)/LTTngUst.class \
		org_lttng_ust_jul_LTTngUst.h liblttng-ust-jul.jar

clean-local:
	rm -f org_lttng_ust_jul_LTTngUst.h
	rm -f liblttng-ust-jul.jar
	rm -f org/lttng/ust/jul/*.class

LTTngUst.c: org_lttng_ust_jul_LTTngUst.h

$(LTTNG_JUL_DESTDIR)/LTTngUst.class: $(LTTNG_JUL_SRCDIR)/LTTngUst.java
	$(JCC)/javac -d "$(builddir)" "$(LTTNG_JUL_SRCDIR)/LTTngUst.java"

$(LTTNG_JUL_DESTDIR)/LTTngAgent.class: $(LTTNG_JUL_SRCDIR)/LTTngAgent.java
	$(JCC)/javac -d "$(builddir)" "$(LTTNG_JUL_SRCDIR)/LTTngAgent.java"

org_lttng_ust_jul_LTTngUst.h: $(LTTNG_JUL_DESTDIR)/LTTngUst.class
	$(JCC)/javah org.lttng.ust.jul.LTTngUst

liblttng-ust-jul.jar: $(LTTNG_JUL_DESTDIR)/LTTngUst.class $(LTTNG_JUL_DESTDIR)/LTTngAgent.class
	$(JCC)/jar cf liblttng-ust-jul.jar \
		$(LTTNG_JUL_DESTDIR)/*.class

endif
