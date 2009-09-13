INCLUDES = -I$(top_builddir)/share -I$(top_builddir)/libust \
	$(KCOMPAT_CFLAGS) $(URCU_CFLAGS)

noinst_PROGRAMS = basic
basic_SOURCES = basic.c
basic_LDADD = $(top_builddir)/libust/libust.la $(URCU_LIBS)

noinst_SCRIPTS = run
EXTRA_DIST = run
