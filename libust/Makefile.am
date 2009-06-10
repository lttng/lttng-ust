lib_LTLIBRARIES = libust.la
libust_la_SOURCES = marker.c marker.h tracepoint.c tracepoint.h immediate.h channels.c channels.h marker-control.c marker-control.h relay.c relay.h tracer.c tracer.h tracercore.c tracercore.h serialize.c tracectl.c $(top_builddir)/libustcomm/ustcomm.c $(top_builddir)/share/kref.c $(top_builddir)/share/usterr.c
libust_la_LDFLAGS = -no-undefined -version-info 0:0:0
libust_la_LIBADD = @URCU_PATH@@URCU_LIB@ -lpthread

INCLUDES = -I$(top_builddir)/share
INCLUDES += -I$(top_builddir)/libustcomm
INCLUDES += -I@URCU_PATH@
INCLUDES += -I@KCOMPAT_PATH@
