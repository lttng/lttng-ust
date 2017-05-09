AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/tests/utils

noinst_LTLIBRARIES = libgcc-wh.la
libgcc_wh_la_SOURCES = c.c d.c

noinst_PROGRAMS = test-gcc-wh
test_gcc_wh_SOURCES = main.c b.c
test_gcc_wh_LDADD = $(top_builddir)/tests/utils/libtap.a \
	$(builddir)/libgcc-wh.la

noinst_SCRIPTS = test_gcc_weak_hidden
CLEANFILES = $(noinst_SCRIPTS)
EXTRA_DIST = test_gcc_weak_hidden.in

$(noinst_SCRIPTS): %: %.in
	$(SED) "s#@ABSTOPSRCDIR@#$(abs_top_srcdir)#g" < $< > $@
	chmod +x $@
