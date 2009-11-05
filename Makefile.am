ACLOCAL_AMFLAGS = -I m4
SUBDIRS = libust tests libmallocwrap ustd ustctl libinterfork include

EXTRA_DIST = doc libust.ldscript.in libust-initializer.c
dist_bin_SCRIPTS = usttrace

ldscriptsdir = $(libdir)
ldscripts_DATA = libust.so libust-initializer.o

CLEANFILES = $(ldscripts_DATA)

libust_FORMAT := $(shell case $(shell uname -m) in (i*86) echo elf32-i386 ;; (x86_64) echo elf64-x86-64 ;; (ppc) echo elf32-powerpc ;; (ppc64) echo elf64-powerpc ;; (s390) echo elf32-s390 ;; (s390x) echo elf64-s390 ;; esac)
libust.so: libust.ldscript.in
	$(SED) -e "s@\@FORMAT\@@${libust_FORMAT}@" -e "s@\@PATH\@@${libdir}@g" < $< > $@

libust-initializer.o: libust-initializer.c
	$(CC) -c $(CFLAGS) -o $@ $<
