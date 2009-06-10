noinst_PROGRAMS = hello
hello_SOURCES = hello.c tp.c tp.h
hello_LDADD = $(top_builddir)/libust/libust.la @URCU_PATH@@URCU_LIB@

INCLUDES = -I$(top_builddir)/share
INCLUDES += -I@URCU_PATH@
INCLUDES += -I@KCOMPAT_PATH@
INCLUDES += -I$(top_builddir)/libust
