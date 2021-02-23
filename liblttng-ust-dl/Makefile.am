AM_CFLAGS += -I$(srcdir) -fno-strict-aliasing

lib_LTLIBRARIES = liblttng-ust-dl.la
liblttng_ust_dl_la_SOURCES = \
	lttng-ust-dl.c \
	ust_dl.c \
	ust_dl.h

liblttng_ust_dl_la_LIBADD = \
	$(top_builddir)/liblttng-ust/liblttng-ust.la \
	$(DL_LIBS)

liblttng_ust_dl_la_CFLAGS = -DUST_COMPONENT=liblttng-ust-dl $(AM_CFLAGS)
liblttng_ust_dl_la_LDFLAGS = -version-info $(LTTNG_UST_LIBRARY_VERSION)
