# tracepoint provider
AM_CPPFLAGS = $(PYTHON_INCLUDE) -I$(top_srcdir)/include/ \
	-I$(top_builddir)/include/
AM_CFLAGS = -fno-strict-aliasing
lib_LTLIBRARIES = liblttng-ust-python-agent.la
liblttng_ust_python_agent_la_SOURCES = lttng_ust_python.c lttng_ust_python.h
liblttng_ust_python_agent_la_LIBADD = -lc -llttng-ust \
	-L$(top_builddir)/liblttng-ust/.libs

# Use setup.py for the installation instead of Autoconf.
# This ease the installation process and assure a *pythonic*
# installation.
agent_path=lttngust
all-local:
	$(PYTHON) setup.py build --verbose

install-exec-local:
	if [ "$(DESTDIR)" = "" ]; then \
		$(PYTHON) setup.py install --prefix=$(prefix) --record install_files.txt  --verbose --no-compile $(DISTSETUPOPTS);  \
	else \
		$(PYTHON) setup.py install --root=$(DESTDIR) --verbose install_files.txt  --prefix=$(prefix) --no-compile $(DISTSETUPOPTS); \
	fi
clean-local:
	rm -rf build

uninstall-local:
	cat install_files.txt | xargs rm -rf
	rm -rf $(DESTDIR)$(pkgpythondir)

EXTRA_DIST=$(agent_path)

# Remove automake generated file before dist
dist-hook:
	rm -rf $(distdir)/$(agent_path)/__init__.py
