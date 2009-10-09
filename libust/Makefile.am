INCLUDES = -I$(top_builddir)/share -I$(top_builddir)/libustcomm

lib_LTLIBRARIES = libust.la
libust_la_SOURCES = marker.c marker.h tracepoint.c tracepoint.h immediate.h channels.c channels.h marker-control.c marker-control.h relay.c relay.h tracer.c tracer.h tracercore.c tracercore.h serialize.c tracectl.c $(top_builddir)/libustcomm/ustcomm.c $(top_builddir)/share/usterr.h
libust_la_LDFLAGS = -no-undefined -version-info 0:0:0
libust_la_LIBADD = -lpthread
libust_la_CFLAGS = -DUST_COMPONENT="libust"
