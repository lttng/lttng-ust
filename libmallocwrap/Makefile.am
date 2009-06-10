INCLUDES = -I$(top_builddir)/share -I$(top_builddir)/libust \
	$(KCOMPAT_CFLAGS) $(URCU_CFLAGS)

lib_LTLIBRARIES = libmallocwrap.la
libmallocwrap_la_SOURCES = mallocwrap.c
libmallocwrap_la_LIBADD = -ldl
noinst_SCRIPTS = run
