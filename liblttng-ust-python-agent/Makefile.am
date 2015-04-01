# inputs/outputs
LTTNGUST_PY_PACKAGE_DIR = $(srcdir)/lttngust
LTTNGUST_PY_PACKAGE_FILES = agent.py cmd.py debug.py loghandler.py
LTTNGUST_PY_PACKAGE_SRC = \
	$(addprefix $(LTTNGUST_PY_PACKAGE_DIR)/,$(LTTNGUST_PY_PACKAGE_FILES))
INIT_PY_IN = $(srcdir)/__init__.py.in
INIT_PY = __init__.py

# dist files
EXTRA_DIST = $(INIT_PY_IN) $(LTTNGUST_PY_PACKAGE_SRC)

# __init__.py with proper version string
all-local: $(INIT_PY)

$(INIT_PY): $(INIT_PY_IN)
	$(SED) "s/@LTTNG_UST_VERSION@/$(PACKAGE_VERSION)/g" < $< > $@

# Python package
nodist_lttngust_PYTHON = $(LTTNGUST_PY_PACKAGE_SRC) $(INIT_PY)
lttngustdir = $(pythondir)/lttngust

# tracepoint provider
AM_CPPFLAGS = $(PYTHON_INCLUDE) -I$(top_srcdir)/include/ \
	-I$(top_builddir)/include/
AM_CFLAGS = -fno-strict-aliasing
lib_LTLIBRARIES = liblttng-ust-python-agent.la
liblttng_ust_python_agent_la_SOURCES = lttng_ust_python.c lttng_ust_python.h
liblttng_ust_python_agent_la_LIBADD = -lc -llttng-ust \
	-L$(top_builddir)/liblttng-ust/.libs

CLEANFILES = $(INIT_PY)
