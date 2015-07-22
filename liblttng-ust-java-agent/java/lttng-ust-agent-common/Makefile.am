JAVAROOT = .

pkgpath = org/lttng/ust/agent

jarfile_version = 1.0.0
jarfile_manifest = $(srcdir)/Manifest.txt
jarfile_symlink = lttng-ust-agent-common.jar
jarfile = lttng-ust-agent-common-$(jarfile_version).jar


jardir = $(datadir)/java

dist_noinst_JAVA = $(pkgpath)/AbstractLttngAgent.java \
				   $(pkgpath)/ILttngAgent.java \
				   $(pkgpath)/ILttngHandler.java \
				   $(pkgpath)/LTTngAgent.java \
				   $(pkgpath)/client/ISessiondCommand.java \
				   $(pkgpath)/client/ISessiondResponse.java \
				   $(pkgpath)/client/LttngTcpSessiondClient.java \
				   $(pkgpath)/client/SessiondDisableHandler.java \
				   $(pkgpath)/client/SessiondEnableHandler.java \
				   $(pkgpath)/client/SessiondHeaderCommand.java \
				   $(pkgpath)/client/SessiondListLoggersResponse.java

dist_noinst_DATA = $(jarfile_manifest)

jar_DATA = $(jarfile)

classes = $(pkgpath)/*.class $(pkgpath)/client/*.class

$(jarfile):
	$(JAR) cfm $(JARFLAGS) $@ $(jarfile_manifest) $(classes) && rm -f $(jarfile_symlink) && $(LN_S) $@ $(jarfile_symlink)

all-local:

install-data-hook:
	cd $(DESTDIR)/$(jardir) && rm -f $(jarfile_symlink) && $(LN_S) $(jarfile) $(jarfile_symlink)

uninstall-hook:
	cd $(DESTDIR)/$(jardir) && rm -f $(jarfile_symlink)

CLEANFILES = $(jarfile) $(pkgpath)/*.class $(pkgpath)/client/*.class
