bin_PROGRAMS = hello
hello_SOURCES = hello.c tp.c tp.h $(top_builddir)/share/kref.c
hello_LDADD = $(top_builddir)/libmarkers/libmarkers.la $(top_builddir)/libtracectl/libtracectl.la $(top_builddir)/libtracing/libtracing.la @URCU_PATH@/liburcu.so
##hello_LDFLAGS = -L$(top_builddir)/libmarkers

INCLUDES = -I$(top_builddir)/share
INCLUDES += -I@URCU_PATH@
INCLUDES += -I@KCOMPAT_PATH@
INCLUDES += -I$(top_builddir)/libtracing
INCLUDES += -I$(top_builddir)/libmarkers
INCLUDES += -I$(top_builddir)/libtracectl
