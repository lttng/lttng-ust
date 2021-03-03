# SPDX-License-Identifier: LGPL-2.1-only

# tracepoint provider: always built/installed (does not depend on Python per se)
AM_CFLAGS += -I$(srcdir) -fno-strict-aliasing

lib_LTLIBRARIES = liblttng-ust-python-agent.la

liblttng_ust_python_agent_la_SOURCES = lttng_ust_python.c lttng_ust_python.h
liblttng_ust_python_agent_la_LIBADD = -lc \
	$(top_builddir)/liblttng-ust/liblttng-ust.la

# Follow the main library soname for co-installability
liblttng_ust_python_agent_la_LDFLAGS = -version-info $(LTTNG_UST_LIBRARY_VERSION)
