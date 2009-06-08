bin_PROGRAMS = ustd
ustd_SOURCES = lowlevel.c localerr.h ustd.c ustd.h $(top_builddir)/libustcomm/ustcomm.c $(top_builddir)/libustcomm/ustcomm.h $(top_builddir)/share/kref.c
ustd_LDFLAGS = -lpthread

INCLUDES = -I$(top_builddir)/share
INCLUDES += -I@URCU_PATH@
INCLUDES += -I@KCOMPAT_PATH@
INCLUDES += -I$(top_builddir)/libust
INCLUDES += -I$(top_builddir)/libustcomm
