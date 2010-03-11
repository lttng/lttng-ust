ACLOCAL_AMFLAGS = -I m4

# The order here is tricky. SUBDIRS applies both to compilation and
# installation. Programs depending on the libs must be built after
# libust and '.' (that contains the linker script). However, '.'
# must be installed after libust so it can overwrite libust.so with
# the linker script.
SUBDIRS = snprintf libustcomm libust . tests libmallocwrap ustd ustctl libinterfork include

EXTRA_DIST = doc libust.ldscript.in libust-initializer.c
dist_bin_SCRIPTS = usttrace

ldscriptsdir = $(libdir)
ldscripts_DATA = libust.so libust-initializer.o

CLEANFILES = $(ldscripts_DATA) ./tests/libust-initializer.Po

libust.so: libust.ldscript.in
	$(SED) -e "s@\@FORMAT\@@$(LIBFORMAT)@" < $< > $@

# It is very important to compile the initializer with PIC otherwise we
# may get obscure errors when linking to shared libraries.
libust-initializer.o: libust-initializer.c
	$(CC) $(CFLAGS) -fPIC -c -I$(top_srcdir)/include -o $@ $<
