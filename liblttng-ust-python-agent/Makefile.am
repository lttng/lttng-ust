
AM_CPPFLAGS = $(PYTHON_INCLUDE) -I$(top_srcdir)/include/
AM_CFLAGS = -fno-strict-aliasing

EXTRA_DIST = lttng_agent.py.in

nodist_lttng_agent_PYTHON = lttng_agent.py
lttng_agentdir = $(pythondir)

lib_LTLIBRARIES = liblttng-ust-python-agent.la

nodist_liblttng_ust_python_agent_la_SOURCES = lttng_agent.py
liblttng_ust_python_agent_la_SOURCES = lttng_ust_python.c lttng_ust_python.h
liblttng_ust_python_agent_la_LIBADD = -lc -llttng-ust \
		-L$(top_builddir)/liblttng-ust/.libs

all:
	$(SED) 's|LIBDIR_STR|$(libdir)|g' < lttng_agent.py.in > lttng_agent.py

CLEANFILES = lttng_agent.py
