AM_CFLAGS += -I$(srcdir) -fno-strict-aliasing

lib_LTLIBRARIES = liblttng-ust-cyg-profile.la \
	liblttng-ust-cyg-profile-fast.la

liblttng_ust_cyg_profile_la_SOURCES = \
	lttng-ust-cyg-profile.c \
	lttng-ust-cyg-profile.h

liblttng_ust_cyg_profile_la_LIBADD = \
	$(top_builddir)/liblttng-ust/liblttng-ust.la \
	$(DL_LIBS)

liblttng_ust_cyg_profile_fast_la_SOURCES = \
	lttng-ust-cyg-profile-fast.c \
	lttng-ust-cyg-profile-fast.h

liblttng_ust_cyg_profile_fast_la_LIBADD = \
	$(top_builddir)/liblttng-ust/liblttng-ust.la \
	$(DL_LIBS)

dist_noinst_SCRIPTS = run run-fast
