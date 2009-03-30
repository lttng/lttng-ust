lib_LTLIBRARIES = libtracectl.la
libtracectl_la_SOURCES = marker-control.c localerr.h tracectl.c ../libustcomm/ustcomm.c ../libustcomm/ustcomm.h

INCLUDES = -I$(top_builddir)/share
INCLUDES += -I@URCU_PATH@
INCLUDES += -I@KCOMPAT_PATH@
INCLUDES += -I$(top_builddir)/libtracing
INCLUDES += -I$(top_builddir)/libmarkers
INCLUDES += -I$(top_builddir)/libustcomm
