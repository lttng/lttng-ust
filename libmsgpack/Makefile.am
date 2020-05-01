# SPDX-License-Identifier: LGPL-2.1-only

AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_builddir)/include
AM_CFLAGS += -fno-strict-aliasing

noinst_LTLIBRARIES = libmsgpack.la

libmsgpack_la_SOURCES = \
	msgpack.c msgpack.h

libmsgpack_la_CFLAGS = -DUST_COMPONENT="libmsgpack" $(AM_CFLAGS)
