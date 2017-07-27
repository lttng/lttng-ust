# Man pages are only built if they are enabled at configure time.
#
# They should always be built before creating a distribution tarball.

# Function which adds the source directory prefix and adds a given suffix:
manaddsuffix = $(addsuffix $(1),$(addprefix $(srcdir)/,$(2)))

# List only the names without the .*.txt extension here:
MAN1_NAMES = \
	lttng-gen-tp
MAN3_NAMES = \
	lttng-ust \
	tracef \
	tracelog \
	lttng-ust-dl \
	lttng-ust-cyg-profile

# troff man pages:
MAN3_TROFF = do_tracepoint.3 tracepoint.3 tracepoint_enabled.3

# AsciiDoc sources and outputs:
MAN1_TXT = $(call manaddsuffix,.1.txt,$(MAN1_NAMES))
MAN3_TXT = $(call manaddsuffix,.3.txt,$(MAN3_NAMES))
MAN_TXT = $(MAN1_TXT) $(MAN3_TXT) $(MAN8_TXT)
MAN_XML = $(patsubst $(srcdir)/%.txt,%.xml,$(MAN_TXT))

# Common AsciiDoc source files:
COMMON_TXT = \
	$(srcdir)/common-footer.txt \
	$(srcdir)/common-authors.txt \
	$(srcdir)/common-copyrights.txt \
	$(srcdir)/log-levels.txt \
	$(srcdir)/tracef-tracelog-limitations.txt

# AsciiDoc configuration and XSL files:
ASCIIDOC_CONF = $(srcdir)/asciidoc.conf
XSL_FILE = $(srcdir)/manpage.xsl

# Common dependencies:
COMMON_DEPS = $(ASCIIDOC_CONF) $(COMMON_TXT)

# Man pages destinations:
MAN1 = $(addsuffix .1,$(MAN1_NAMES))
MAN3 = $(addsuffix .3,$(MAN3_NAMES))
MAN = $(MAN1) $(MAN3)

if MAN_PAGES_OPT
# At this point, we know the user asked to build the man pages.
if HAVE_ASCIIDOC_XMLTO
# Tools to execute:
ADOC = $(ASCIIDOC) -f $(ASCIIDOC_CONF) -d manpage \
	-a lttng_version="$(PACKAGE_VERSION)" \
	-a lttng_ust_register_timeout="@LTTNG_UST_DEFAULT_CONSTRUCTOR_TIMEOUT_MS@"

ADOC_DOCBOOK = $(ADOC) -b docbook
XTO = $(XMLTO) -m $(XSL_FILE) man

# Recipes:
%.1.xml: $(srcdir)/%.1.txt $(COMMON_DEPS)
	$(ADOC_DOCBOOK) -o $@ $<

%.1: %.1.xml $(XSL_FILE)
	$(XTO) $<

%.3.xml: $(srcdir)/%.3.txt $(COMMON_DEPS)
	$(ADOC_DOCBOOK) -o $@ $<

%.3: %.3.xml $(XSL_FILE)
	$(XTO) $<

# Only clean the generated files if we have the tools to generate them again.
CLEANFILES = $(MAN_XML) $(MAN)
else # HAVE_ASCIIDOC_XMLTO
# Create man page targets used to stop the build if we want to
# build the man pages, but we don't have the necessary tools to do so.
ERR_MSG = "Error: Cannot build target because asciidoc or xmlto tool is missing."
ERR_MSG += "Make sure both tools are installed and run the configure script again."

%.1: $(srcdir)/%.1.txt $(COMMON_DEPS)
	@echo $(ERR_MSG)
	@false

%.3: $(srcdir)/%.3.txt $(COMMON_DEPS)
	@echo $(ERR_MSG)
	@false
endif # HAVE_ASCIIDOC_XMLTO
endif # MAN_PAGES_OPT

# Start with empty distributed/installed man pages:
dist_man1_MANS =
dist_man3_MANS =
EXTRA_DIST =

if MAN_PAGES_OPT
# Building man pages: we can install and distribute them.
dist_man1_MANS += $(MAN1)
dist_man3_MANS += $(MAN3) $(MAN3_TROFF)
else # MAN_PAGES_OPT
# Those are not known by automake yet because dist_man3_MANS is empty
# at this point, so make sure they are distributed.
EXTRA_DIST += $(MAN3_TROFF)
endif # MAN_PAGES_OPT

if !MAN_PAGES_OPT
dist-hook:
	@echo "Error: Please enable the man pages before creating a distribution tarball."
	@false
endif # !MAN_PAGES_OPT

# Always distribute the source files.
EXTRA_DIST += $(MAN_TXT) $(COMMON_TXT) $(XSL_FILE) $(ASCIIDOC_CONF)
