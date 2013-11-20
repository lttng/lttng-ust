# 
# Copyright (C) 2013 - David Goulet <dgoulet@efficios.com>
#
# THIS MATERIAL IS PROVIDED AS IS, WITH ABSOLUTELY NO WARRANTY EXPRESSED OR
# IMPLIED. ANY USE IS AT YOUR OWN RISK.
#
# Permission is hereby granted to use or copy this program for any purpose,
# provided the above notices are retained on all copies.  Permission to modify
# the code and to distribute modified code is granted, provided the above
# notices are retained, and a notice that the code was modified is included
# with the above copyright notice.
#
# This Makefile is not using automake so that users may see how to build a
# program with tracepoint provider probes as stand-alone shared objects.
#
# This makefile is purposefully kept simple to support GNU and BSD make.
#

# Default JUL jar name.
JARFILE=liblttng-ust-jul.jar

# Check if the top level makefile overrides the JUL Jar file name.
ifneq "$(JAVA_JARFILE_OVERRIDE)" ""
	JARFILE=$(JAVA_JARFILE_OVERRIDE)
endif

# Check if the top level makefile overrides the JUL classpath.
ifeq "$(JAVA_CLASSPATH_OVERRIDE)" ""
	CLASSPATH=/usr/local/lib/lttng/java/$(JARFILE):/usr/lib/lttng/java/$(JARFILE)
else
	CLASSPATH=$(JAVA_CLASSPATH_OVERRIDE)/$(JARFILE)
endif

JFLAGS = -g
JC = javac -cp "$(CLASSPATH):."
.SUFFIXES: .java .class
.java.class:
	$(JC) $(JFLAGS) $*.java

CLASSES = Hello.java

all: classes

classes: $(CLASSES:.java=.class)

.PHONY: clean
clean:
	$(RM) *.class
