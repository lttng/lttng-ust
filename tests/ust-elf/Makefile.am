AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/tests/utils

noinst_PROGRAMS = prog
prog_SOURCES = prog.c
prog_LDADD = $(top_builddir)/liblttng-ust/liblttng-ust.la \
	$(top_builddir)/tests/utils/libtap.a

noinst_SCRIPTS = test_ust_elf
CLEANFILES = $(noinst_SCRIPTS)
EXTRA_DIST = test_ust_elf.in \
	$(srcdir)/data/main.c \
	$(srcdir)/data/aarch64_be/main.elf \
	$(srcdir)/data/aarch64_be/main.elf.debug \
	$(srcdir)/data/armeb/main.elf \
	$(srcdir)/data/armeb/main.elf.debug \
	$(srcdir)/data/x86/main.elf \
	$(srcdir)/data/x86/main.elf.debug \
	$(srcdir)/data/x86_64/main.elf \
	$(srcdir)/data/x86_64/main.elf.debug \
	$(srcdir)/data/pic/hello.exec \
	$(srcdir)/data/pic/hello.pie \
	$(srcdir)/data/pic/hello.pic \
	$(srcdir)/data/pic/hello.c \
	$(srcdir)/data/pic/libhello.c

$(noinst_SCRIPTS): %: %.in
	$(SED) "s#@ABSTOPSRCDIR@#$(abs_top_srcdir)#g" < $< > $@
	chmod +x $@
