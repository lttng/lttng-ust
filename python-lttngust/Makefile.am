# Use setup.py for the installation instead of Autoconf.
# This ease the installation process and assure a *pythonic*
# installation.
all-local:
	$(PYTHON) setup.py build --verbose

install-exec-local:
	@opts="--prefix=$(prefix) --verbose --no-compile $(DISTSETUPOPTS)"; \
	if [ "$(DESTDIR)" != "" ]; then \
		opts="$$opts --root=$(DESTDIR)"; \
	fi; \
	$(PYTHON) setup.py install $$opts;

clean-local:
	rm -rf $(builddir)/build

# Distutils' setup.py does not include an uninstall target, we thus need to do
# it manually. We fake an install in a temporary folder and use the generated
# tree structure to infere the actual location within the install prefix.
# 1. Create temporary file and folder
# 2. Set the root install folder for a temporary folder
# 3. Install in that temporary folder and record all the files installed
# 4. If DESTDIR is set, prepend it to the paths of the install files
# 5. Remove the installed files and the Python package folder
# 6. Remove the files created by this target

uninstall-local:
	$(eval TMP_INSTALLED_FILES:=$(shell mktemp $(builddir)/tmp-installed-files-XXXXXX))
	$(eval TMP_INSTALL_DIR:=$(shell mktemp -d $(builddir)/tmp-install-dir-XXXXXX))
	$(eval TMP_BUILD_DIR:=$(shell mktemp -d $(builddir)/tmp-build-dir-XXXXXX))
	@opts="--root=$(TMP_INSTALL_DIR) --prefix=$(prefix) --record $(TMP_INSTALLED_FILES) --no-compile $(DISTSETUPOPTS)"; \
	if [ "$(DESTDIR)" != "" ]; then \
		opts="$$opts --root=$(DESTDIR)"; \
	else \
		opts="$$opts --root=$(TMP_INSTALL_DIR)"; \
	fi; \
	$(PYTHON) setup.py build --build-base $(TMP_BUILD_DIR) install $$opts > /dev/null || true
	
	if [ "$(DESTDIR)" != "" ]; then \
		$(SED) -i "s|^|$(DESTDIR)/|g" $(TMP_INSTALLED_FILES); \
	fi
	
	cat $(TMP_INSTALLED_FILES) | xargs rm -rf || true
	$(GREP) "__init__.py" $(TMP_INSTALLED_FILES) | xargs dirname | xargs rm -rf || true
	rm -f $(TMP_INSTALLED_FILES)
	rm -rf $(TMP_INSTALL_DIR)
	rm -rf $(TMP_BUILD_DIR)
