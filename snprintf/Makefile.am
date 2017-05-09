AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/libustcomm
AM_CFLAGS += -fno-strict-aliasing

noinst_LTLIBRARIES = libustsnprintf.la
libustsnprintf_la_SOURCES = \
	fflush.c \
	fileext.h \
	floatio.h \
	fvwrite.c \
	fvwrite.h \
	local.h \
	mbrtowc_sb.c \
	snprintf.c \
	various.h \
	vfprintf.c \
	wcio.h \
	wsetup.c \
	core.c \
	patient_write.c

libustsnprintf_la_LDFLAGS = -no-undefined -static
libustsnprintf_la_CFLAGS = -DUST_COMPONENT="lttng_ust_snprintf" -fPIC $(AM_CFLAGS)
