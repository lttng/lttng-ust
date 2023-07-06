# SPDX-FileCopyrightText: 2023 EfficiOS, Inc
#
# SPDX-License-Identifier: LGPL-2.1-only

JAVAROOT = .
AM_JAVACFLAGS = -classpath $(CLASSPATH):$(builddir)/../lttng-ust-agent-common/lttng-ust-agent-common.jar

pkgpath = org/lttng/ust/agent/jul

jarfile_version = 1.0.0
jarfile_manifest = $(srcdir)/Manifest.txt
jarfile_symlink = lttng-ust-agent-jul.jar
jarfile = lttng-ust-agent-jul-$(jarfile_version).jar

jardir = $(datadir)/java

juljniout = ../../jni/jul

dist_noinst_JAVA = $(pkgpath)/LttngJulAgent.java \
				   $(pkgpath)/LttngJulApi.java \
				   $(pkgpath)/LttngLogHandler.java

dist_noinst_DATA = \
	$(jarfile_manifest) \
	$(jarfile_manifest).license

jar_DATA = $(jarfile)

stamp = jul-jni-header.stamp
classes = $(pkgpath)/*.class

$(jarfile): classnoinst.stamp
	$(JAR) cfm $(JARFLAGS) $@ $(jarfile_manifest) $(classes) && rm -f $(jarfile_symlink) && $(LN_S) $@ $(jarfile_symlink)

if !HAVE_JAVAH
# If we don't have javah, assume we are running openjdk >= 10 and use javac
# to generate the jni header file.
AM_JAVACFLAGS += -h $(juljniout)
else
jul-jni-header.stamp: $(dist_noinst_JAVA)
	$(JAVAH) -classpath $(CLASSPATH):$(srcdir) -d $(juljniout) $(JAVAHFLAGS) org.lttng.ust.agent.jul.LttngJulApi && \
	echo "JUL JNI header generated" > jul-jni-header.stamp

all-local: $(stamp)
endif

install-data-hook:
	cd $(DESTDIR)/$(jardir) && rm -f $(jarfile_symlink) && $(LN_S) $(jarfile) $(jarfile_symlink)

uninstall-hook:
	cd $(DESTDIR)/$(jardir) && rm -f $(jarfile_symlink)

CLEANFILES = *.jar \
	$(pkgpath)/*.class \
	jul-jni-header.stamp \
	$(juljniout)/org_lttng_ust_agent_jul_LttngJulApi.h
