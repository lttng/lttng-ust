INCLUDES = -I$(top_builddir)/share -I$(top_builddir)/libust \
	$(KCOMPAT_CFLAGS) $(URCU_CFLAGS)

noinst_PROGRAMS = hello
hello_SOURCES = hello.c tp.c tp.h
hello_LDADD = $(top_builddir)/libust/libust.la $(URCU_LIBS)

noinst_SCRIPTS = run
EXTRA_DIST = run
