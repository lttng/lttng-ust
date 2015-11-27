# Use setup.py for the installation instead of Autoconf.
# This ease the installation process and assure a *pythonic*
# installation.
agent_path=lttngust
all-local:
	$(PYTHON) setup.py build --verbose

install-exec-local:
	@opts="--prefix=$(prefix) --verbose --no-compile $(DISTSETUPOPTS)"; \
	if [ "$(DESTDIR)" != "" ]; then \
		opts="$$opts --root=$(DESTDIR)"; \
	fi; \
	$(PYTHON) setup.py install $$opts;

clean-local:
	rm -rf build

uninstall-local:
	rm -rf $(DESTDIR)$(pkgpythondir)

EXTRA_DIST=$(agent_path)

# Remove automake generated file before dist
dist-hook:
	rm -rf $(distdir)/$(agent_path)/__init__.py
