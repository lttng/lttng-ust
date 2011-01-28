ACLOCAL_AMFLAGS = -I config

# The order here is tricky. SUBDIRS applies both to compilation and
# installation. Programs depending on the libs must be built after
# libust and '.' (that contains the linker script). However, '.'
# must be installed after libust so it can overwrite libust.so with
# the linker script.
SUBDIRS = snprintf libustcomm libustctl libust . tests libustinstr-malloc libustconsumer ust-consumerd ustctl libustfork include doc

EXTRA_DIST = libust.ldscript.in libust-initializer.c libust-initializer.h
dist_bin_SCRIPTS = usttrace

ldscriptsdir = $(libdir)
ldscripts_DATA = libust.so libust-initializer.o

CLEANFILES = $(ldscripts_DATA) ./tests/libust-initializer.Po

libust.so: libust.ldscript.in
	$(SED) -e "s@\@FORMAT\@@$(LIBFORMAT)@" < $< > $@

# It is very important to compile the initializer with PIC otherwise we
# may get obscure errors when linking to shared libraries.
libust-initializer.o: libust-initializer.c
	$(CC) $(CFLAGS) -fno-strict-aliasing -fPIC -c -I$(top_srcdir)/include -I$(top_srcdir) -o $@ $<
