JAVAROOT = .

jarfile_manifest = $(srcdir)/Manifest.txt
jarfile = liblttng-ust-agent.jar

jardir = $(datadir)/java

dist_noinst_DATA = $(jarfile_manifest)

jar_DATA = $(jarfile)

$(jarfile):
	$(JAR) cfm $(JARFLAGS) $@ $(jarfile_manifest)
