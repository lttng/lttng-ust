# SPDX-License-Identifier: LGPL-2.1-only

JAVAROOT = .

# Add the UST agent common jar to the classpath
AM_JAVACFLAGS = -classpath $(CLASSPATH):$(builddir)/../lttng-ust-agent-common/lttng-ust-agent-common.jar

# Process the log4j2 annotations of our custom appender
AM_JAVACFLAGS += -processor org.apache.logging.log4j.core.config.plugins.processor.PluginProcessor

pkgpath = org/lttng/ust/agent/log4j2

jarfile_version = 1.0.0
jarfile_manifest = $(srcdir)/Manifest.txt
jarfile_symlink = lttng-ust-agent-log4j2.jar
jarfile = lttng-ust-agent-log4j2-$(jarfile_version).jar

jardir = $(datadir)/java

log4jjniout = ../../jni/log4j

dist_noinst_JAVA = \
	$(pkgpath)/LttngLog4j2Agent.java \
	$(pkgpath)/LttngLog4j2Api.java \
	$(pkgpath)/LttngLogAppender.java

dist_noinst_DATA = $(jarfile_manifest)

jar_DATA = $(jarfile)

classes = $(pkgpath)/*.class

$(jarfile): classnoinst.stamp
	$(JAR) cfm $(JARFLAGS) $@ $(jarfile_manifest) META-INF $(classes) && rm -f $(jarfile_symlink) && $(LN_S) $@ $(jarfile_symlink)

if !HAVE_JAVAH
# If we don't have javah, assume we are running openjdk >= 10 and use javac
# to generate the jni header file.
AM_JAVACFLAGS += -h $(log4jjniout)
else
log4j-jni-header.stamp: $(dist_noinst_JAVA)
	$(JAVAH) -classpath $(CLASSPATH):$(srcdir) -d $(log4jjniout) $(JAVAHFLAGS) org.lttng.ust.agent.log4j2.LttngLog4j2Api && \
	echo "Log4j JNI header generated" > log4j-jni-header.stamp

all-local: log4j-jni-header.stamp
endif

install-data-hook:
	cd $(DESTDIR)/$(jardir) && rm -f $(jarfile_symlink) && $(LN_S) $(jarfile) $(jarfile_symlink)

uninstall-hook:
	cd $(DESTDIR)/$(jardir) && rm -f $(jarfile_symlink)

clean-local:
	rm -rf META-INF

CLEANFILES = *.jar \
	$(classes) \
	log4j-jni-header.stamp \
	$(log4jjniout)/org_lttng_ust_agent_log4j2_LttngLog4j2Api.h
