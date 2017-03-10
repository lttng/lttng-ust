JAVAROOT = .

jarfile_version = 1.0.0
jarfile_manifest = $(srcdir)/Manifest.txt
jarfile_symlink = lttng-ust-agent-all.jar
jarfile = lttng-ust-agent-all-$(jarfile_version).jar

# Compatibility symlink provided for applications expecting the agent
# jar file installed by UST 2.7.
jarfile_compat_symlink = liblttng-ust-agent.jar

jardir = $(datadir)/java

dist_noinst_DATA = $(jarfile_manifest)

jar_DATA = $(jarfile)

$(jarfile):
	$(JAR) cfm $(JARFLAGS) $@ $(jarfile_manifest) \
		&& rm -f $(jarfile_symlink) && $(LN_S) $@ $(jarfile_symlink) \
		&& rm -f $(jarfile_compat_symlink) && $(LN_S) $(jarfile_symlink) $(jarfile_compat_symlink)

install-data-hook:
	cd $(DESTDIR)/$(jardir) \
		&& rm -f $(jarfile_symlink) && $(LN_S) $(jarfile) $(jarfile_symlink) \
		&& rm -f $(jarfile_compat_symlink) && $(LN_S) $(jarfile_symlink) $(jarfile_compat_symlink)

uninstall-hook:
	cd $(DESTDIR)/$(jardir) && rm -f $(jarfile_symlink) && rm -f $(jarfile_compat_symlink)

CLEANFILES = *.jar
