# SPDX-FileCopyrightText: 2023 EfficiOS, Inc
#
# SPDX-License-Identifier: LGPL-2.1-only

JAVAROOT = .
AM_JAVACFLAGS = -classpath $(CLASSPATH):$(builddir)/../lttng-ust-agent-common/lttng-ust-agent-common.jar

pkgpath = org/lttng/ust/agent/log4j

jarfile_version = 1.0.0
jarfile_manifest = $(srcdir)/Manifest.txt
jarfile_symlink = lttng-ust-agent-log4j.jar
jarfile = lttng-ust-agent-log4j-$(jarfile_version).jar

jardir = $(datadir)/java

log4jjniout = ../../jni/log4j

dist_noinst_JAVA = $(pkgpath)/LttngLog4jAgent.java \
				   $(pkgpath)/LttngLog4jApi.java \
				   $(pkgpath)/LttngLogAppender.java

dist_noinst_DATA = \
	$(jarfile_manifest) \
	$(jarfile_manifest).license

jar_DATA = $(jarfile)

stamp = log4j-jni-header.stamp
classes = $(pkgpath)/*.class

$(jarfile): classnoinst.stamp
	$(JAR) cfm $(JARFLAGS) $@ $(jarfile_manifest) $(classes) && rm -f $(jarfile_symlink) && $(LN_S) $@ $(jarfile_symlink)

if !HAVE_JAVAH
# If we don't have javah, assume we are running openjdk >= 10 and use javac
# to generate the jni header file.
AM_JAVACFLAGS += -h $(log4jjniout)
else
log4j-jni-header.stamp: $(dist_noinst_JAVA)
	$(JAVAH) -classpath $(CLASSPATH):$(srcdir) -d $(log4jjniout) $(JAVAHFLAGS) org.lttng.ust.agent.log4j.LttngLog4jApi && \
	echo "Log4j JNI header generated" > log4j-jni-header.stamp

all-local: $(stamp)
endif

install-data-hook:
	cd $(DESTDIR)/$(jardir) && rm -f $(jarfile_symlink) && $(LN_S) $(jarfile) $(jarfile_symlink)

uninstall-hook:
	cd $(DESTDIR)/$(jardir) && rm -f $(jarfile_symlink)

CLEANFILES = *.jar \
	$(pkgpath)/*.class \
	log4j-jni-header.stamp \
	$(log4jjniout)/org_lttng_ust_agent_log4j_LttngLog4jApi.h
