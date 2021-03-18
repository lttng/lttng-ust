# SPDX-License-Identifier: LGPL-2.1-only

INSTALLED_FILES=$(builddir)/installed_files.txt

STATIC_BINDINGS_DEPS = \
	lttngust/agent.py \
	lttngust/cmd.py \
	lttngust/compat.py \
	lttngust/debug.py \
	lttngust/loghandler.py

all-local: build-python-bindings.stamp

copy-static-deps.stamp: $(addprefix $(srcdir)/, $(STATIC_BINDINGS_DEPS))
	@if [ x"$(srcdir)" != x"$(builddir)" ]; then \
		for file in $(STATIC_BINDINGS_DEPS); do \
			cp -f $(srcdir)/$$file $(builddir)/$$file; \
		done; \
	fi
	touch $@

# Use setup.py for the installation instead of Autoconf.
# This ease the installation process and assure a *pythonic*
# installation.
build-python-bindings.stamp: copy-static-deps.stamp
	$(PYTHON) $(builddir)/setup.py build --force
	touch $@

install-exec-local: build-python-bindings.stamp
	@opts="--prefix=$(prefix) --record $(INSTALLED_FILES) --verbose --no-compile $(DISTSETUPOPTS)"; \
	if [ "$(DESTDIR)" != "" ]; then \
		opts="$$opts --root=$(DESTDIR)"; \
	fi; \
	$(PYTHON) $(builddir)/setup.py install $$opts;

clean-local:
	rm -rf $(builddir)/build
	@if [ x"$(srcdir)" != x"$(builddir)" ]; then \
		for file in $(STATIC_BINDINGS_DEPS); do \
			rm -f $(builddir)/$$file; \
		done; \
	fi

# Distutils' setup.py does not include an uninstall target, we thus need to do
# it manually. We save the path of the files that were installed during the install target
# and delete them during the uninstallation.
uninstall-local:
	if [ "$(DESTDIR)" != "" ]; then \
		$(SED) -i "s|^|$(DESTDIR)/|g" $(INSTALLED_FILES); \
	fi
	cat $(INSTALLED_FILES) | xargs rm -rf || true
	$(GREP) "__init__.py" $(INSTALLED_FILES) | xargs dirname | xargs rm -rf || true
	rm -f $(INSTALLED_FILES)

EXTRA_DIST = $(STATIC_BINDINGS_DEPS)

CLEANFILES = \
	build-python-bindings.stamp \
	copy-static-deps.stamp
