lib_LTLIBRARIES = libmarkers.la
libmarkers_la_SOURCES = marker.c tracepoint.c immediate.h jhash.h rcupdate.h marker.h tracepoint.h
libmarkers_la_LIBADD = @URCU_PATH@/liburcu.so

INCLUDES = -I$(top_builddir)/share
INCLUDES += -I@URCU_PATH@
INCLUDES += -I@KCOMPAT_PATH@
INCLUDES += -I$(top_builddir)/libtracing
