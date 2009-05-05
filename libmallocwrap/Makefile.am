lib_LTLIBRARIES = libmallocwrap.la
libmallocwrap_la_SOURCES = mallocwrap.c
libmallocwrap_la_LIBADD = -ldl
noinst_SCRIPTS = run

INCLUDES = -I$(top_builddir)/share
INCLUDES += -I@URCU_PATH@
INCLUDES += -I@KCOMPAT_PATH@
INCLUDES += -I$(top_builddir)/libust
