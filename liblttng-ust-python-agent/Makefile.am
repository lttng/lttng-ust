# tracepoint provider: always built/installed (does not depend on Python per se)
AM_CPPFLAGS = -I$(top_srcdir)/include/ \
	-I$(top_builddir)/include/
AM_CFLAGS += -fno-strict-aliasing
lib_LTLIBRARIES = liblttng-ust-python-agent.la
liblttng_ust_python_agent_la_SOURCES = lttng_ust_python.c lttng_ust_python.h
liblttng_ust_python_agent_la_LIBADD = -lc -llttng-ust \
	-L$(top_builddir)/liblttng-ust/.libs
