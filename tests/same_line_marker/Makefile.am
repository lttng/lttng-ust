AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/libust

noinst_PROGRAMS = same_line_marker
same_line_marker_SOURCES = same_line_marker.c
same_line_marker_LDADD = $(top_builddir)/libust/libust.la $(top_builddir)/libust-initializer.o

noinst_SCRIPTS = run
EXTRA_DIST = run
