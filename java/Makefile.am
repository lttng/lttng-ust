INCLUDES = -I$(top_builddir)/share -I$(top_builddir)/libust

lib_LTLIBRARIES = libustjava.la
libustjava_la_SOURCES = UST.c UST.h
noinst_DATA = UST.java
libustjava_la_LIBADD = -lc -L$(top_builddir)/libust/.libs -lust

all: UST.class

clean-local:
	rm -rf UST.h UST.class

UST.class: UST.java
	javac UST.java

