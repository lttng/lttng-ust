AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/tests/utils

noinst_PROGRAMS = prog
prog_SOURCES = prog.c
prog_LDADD = $(top_builddir)/liblttng-ust/liblttng-ust.la \
	$(top_builddir)/tests/utils/libtap.a

noinst_SCRIPTS = test_ust_elf
CLEANFILES = $(noinst_SCRIPTS)
EXTRA_DIST = test_ust_elf.in $(srcdir)/data/**

$(noinst_SCRIPTS): %: %.in
	sed "s#@TOPSRCDIR@#$(top_srcdir)#g" < $< > $@
	chmod +x $@
