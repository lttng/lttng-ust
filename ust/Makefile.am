bin_PROGRAMS = ust
ust_SOURCES = ust.c $(top_builddir)/libustcomm/ustcomm.c $(top_builddir)/libustcomm/ustcomm.h

#INCLUDES = -I$(top_builddir)/share
#INCLUDES += -I@URCU_PATH@
INCLUDES = $(KCOMPAT_CFLAGS)
#INCLUDES += -I$(top_builddir)/libust
INCLUDES += -I$(top_builddir)/libustcomm
