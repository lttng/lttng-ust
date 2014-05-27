LTTNG_JUL_SRCDIR = $(srcdir)/org/lttng/ust/jul
LTTNG_JUL_DESTDIR = $(builddir)/org/lttng/ust/jul

if BUILD_JNI_INTERFACE

AM_CPPFLAGS = -I$(top_srcdir)/include -I$(builddir) -I$(top_builddir)/include

BUILT_SOURCES = org_lttng_ust_jul_LTTngUst.h
lib_LTLIBRARIES = liblttng-ust-jul-jni.la
liblttng_ust_jul_jni_la_SOURCES = LTTngUst.c lttng_ust_jul.h
nodist_liblttng_ust_jul_jni_la_SOURCES = org_lttng_ust_jul_LTTngUst.h
dist_noinst_DATA = $(LTTNG_JUL_SRCDIR)/LTTngUst.java \
	$(LTTNG_JUL_SRCDIR)/LTTngAgent.java \
	$(LTTNG_JUL_SRCDIR)/LTTngEvent.java \
	$(LTTNG_JUL_SRCDIR)/LTTngLogHandler.java \
	$(LTTNG_JUL_SRCDIR)/LTTngSessiondCmd2_4.java \
	$(LTTNG_JUL_SRCDIR)/LTTngTCPSessiondClient.java \
	$(LTTNG_JUL_SRCDIR)/LTTngThread.java
liblttng_ust_jul_jni_la_LIBADD = -lc -L$(top_builddir)/liblttng-ust/.libs -llttng-ust

lttnglibjava_DATA = liblttng-ust-jul.jar

if HAVE_JAVA_JDK
JCC=$(JAVA_JDK)/bin
else
JCC=javac
endif

all-local: $(LTTNG_JUL_DESTDIR)/LTTngAgent.class \
		$(LTTNG_JUL_DESTDIR)/LTTngUst.class \
		org_lttng_ust_jul_LTTngUst.h \
		liblttng-ust-jul.jar

clean-local:
	rm -f org_lttng_ust_jul_LTTngUst.h
	rm -f liblttng-ust-jul.jar
	rm -f org/lttng/ust/jul/*.class

%.class: %.java
	$(JCC)/javac -d "$(builddir)" $<

LTTNG_AGENT_FILES = $(LTTNG_JUL_SRCDIR)/LTTngAgent.java \
		$(LTTNG_JUL_SRCDIR)/LTTngLogHandler.java \
		$(LTTNG_JUL_SRCDIR)/LTTngEvent.java \
		$(LTTNG_JUL_SRCDIR)/LTTngSessiondCmd2_4.java \
		$(LTTNG_JUL_SRCDIR)/LTTngTCPSessiondClient.java \
		$(LTTNG_JUL_SRCDIR)/LTTngThread.java

$(LTTNG_JUL_DESTDIR)/LTTngAgent.class: $(LTTNG_AGENT_FILES) \
		$(LTTNG_JUL_DESTDIR)/LTTngUst.class
	$(JCC)/javac -d "$(builddir)" $(LTTNG_AGENT_FILES)

org_lttng_ust_jul_LTTngUst.h: $(LTTNG_JUL_DESTDIR)/LTTngUst.class
	$(JCC)/javah org.lttng.ust.jul.LTTngUst

liblttng-ust-jul.jar: $(LTTNG_JUL_DESTDIR)/LTTngAgent.class
	$(JCC)/jar cf liblttng-ust-jul.jar \
		$(LTTNG_JUL_DESTDIR)/*.class

endif
