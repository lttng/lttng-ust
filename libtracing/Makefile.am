lib_LTLIBRARIES = libtracing.la
libtracing_la_SOURCES = channels.c channels.h relay.c relay.h serialize.c tracer.c tracer.h tracercore.c tracercore.h

INCLUDES = -I$(top_builddir)/share
INCLUDES += -I@URCU_PATH@
INCLUDES += -I@KCOMPAT_PATH@
INCLUDES += -I$(top_builddir)/libmarkers
