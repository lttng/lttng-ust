ACLOCAL_AMFLAGS = -I m4
SUBDIRS = libust tests libmallocwrap ustd ustctl libinterfork include

EXTRA_DIST = doc libust.ldscript.in libust-initializer.c
dist_bin_SCRIPTS = usttrace

ldscriptsdir = $(libdir)
ldscripts_DATA = libust.so libust-initializer.o

CLEANFILES = $(ldscripts_DATA) ./tests/libust-initializer.Po

libust.so: libust.ldscript.in
	$(SED) -e "s@\@FORMAT\@@$(LIBFORMAT)@" -e "s@\@PATH\@@${libdir}@g" < $< > $@

libust-initializer.o: libust-initializer.c
	$(CC) $(CFLAGS) -c -I$(top_srcdir)/include -o $@ $<
