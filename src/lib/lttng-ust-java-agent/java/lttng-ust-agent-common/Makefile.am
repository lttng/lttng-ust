# SPDX-FileCopyrightText: 2023 EfficiOS, Inc
#
# SPDX-License-Identifier: LGPL-2.1-only

JAVAROOT = .

pkgpath = org/lttng/ust/agent

jarfile_version = 1.0.0
jarfile_manifest = $(srcdir)/Manifest.txt
jarfile_symlink = lttng-ust-agent-common.jar
jarfile = lttng-ust-agent-common-$(jarfile_version).jar

jardir = $(datadir)/java
jnioutdir = ../../jni/common

dist_noinst_JAVA = $(pkgpath)/AbstractLttngAgent.java \
				   $(pkgpath)/EventNamePattern.java \
				   $(pkgpath)/ILttngAgent.java \
				   $(pkgpath)/ILttngHandler.java \
				   $(pkgpath)/LTTngAgent.java \
				   $(pkgpath)/client/ILttngTcpClientListener.java \
				   $(pkgpath)/client/SessiondCommand.java \
				   $(pkgpath)/client/LttngAgentResponse.java \
				   $(pkgpath)/client/LttngTcpSessiondClient.java \
				   $(pkgpath)/client/SessiondCommandHeader.java \
				   $(pkgpath)/client/SessiondDisableAppContextCommand.java \
				   $(pkgpath)/client/SessiondDisableEventCommand.java \
				   $(pkgpath)/client/SessiondEnableAppContextCommand.java \
				   $(pkgpath)/client/SessiondEnableEventCommand.java \
				   $(pkgpath)/client/SessiondListLoggersCommand.java \
				   $(pkgpath)/context/LttngContextApi.java \
				   $(pkgpath)/context/ContextInfoManager.java \
				   $(pkgpath)/context/ContextInfoSerializer.java \
				   $(pkgpath)/context/IContextInfoRetriever.java \
				   $(pkgpath)/filter/FilterChangeNotifier.java \
				   $(pkgpath)/filter/IFilterChangeListener.java \
				   $(pkgpath)/session/EventRule.java \
				   $(pkgpath)/session/LogLevelSelector.java \
				   $(pkgpath)/utils/LttngUstAgentLogger.java


dist_noinst_DATA = \
	$(jarfile_manifest) \
	$(jarfile_manifest).license

jar_DATA = $(jarfile)

classes = $(pkgpath)/*.class \
		  $(pkgpath)/client/*.class \
		  $(pkgpath)/context/*.class \
		  $(pkgpath)/filter/*.class \
		  $(pkgpath)/session/*.class \
		  $(pkgpath)/utils/*.class

$(jarfile): classnoinst.stamp
	$(JAR) cfm $(JARFLAGS) $@ $(jarfile_manifest) $(classes) && rm -f $(jarfile_symlink) && $(LN_S) $@ $(jarfile_symlink)

if !HAVE_JAVAH
# If we don't have javah, assume we are running openjdk >= 10 and use javac
# to generate the jni header file.
AM_JAVACFLAGS = -h $(jnioutdir)
else
context-jni-header.stamp: $(dist_noinst_JAVA)
	$(JAVAH) -classpath $(CLASSPATH):$(srcdir) -d $(jnioutdir) $(JAVAHFLAGS) org.lttng.ust.agent.context.LttngContextApi && \
	echo "Context API JNI header generated" > context-jni-header.stamp

all-local: context-jni-header.stamp
endif

install-data-hook:
	cd $(DESTDIR)/$(jardir) && rm -f $(jarfile_symlink) && $(LN_S) $(jarfile) $(jarfile_symlink)

uninstall-hook:
	cd $(DESTDIR)/$(jardir) && rm -f $(jarfile_symlink)

CLEANFILES = *.jar \
			 $(pkgpath)/*.class \
			 $(pkgpath)/client/*.class \
			 $(pkgpath)/context/*.class \
			 $(pkgpath)/filter/*.class \
			 $(pkgpath)/session/*.class \
			 $(pkgpath)/utils/*.class \
			 context-jni-header.stamp \
			 $(jnioutdir)/org_lttng_ust_agent_context_LttngContextApi.h
