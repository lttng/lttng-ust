AM_CPPFLAGS = -I$(top_srcdir)/include

lib_LTLIBRARIES = libustcomm.la
libustcomm_la_SOURCES = \
	ustcomm.h \
	ustcomm.c \
	multipoll.h \
	multipoll.c
libustcomm_la_LDFLAGS = -no-undefined -version-info 0:0:0 -static
libustcomm_la_CFLAGS = -DUST_COMPONENT="libustcomm" -fPIC
