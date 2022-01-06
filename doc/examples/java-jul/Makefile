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

# Required JAR files for JUL
JARFILE_JUL=lttng-ust-agent-jul.jar
JARFILE_COMMON=lttng-ust-agent-common.jar

# Check if the top level makefile overrides the JUL Jar file's path.
ifeq "$(JAVA_CLASSPATH_OVERRIDE_JUL)" ""
	JUL_CP = /usr/local/share/java/$(JARFILE_JUL):/usr/share/java/$(JARFILE_JUL)
else
	JUL_CP = $(JAVA_CLASSPATH_OVERRIDE_JUL)/$(JARFILE_JUL)
endif

# Check if the top level makefile overrides the Common Jar file's path.
ifeq "$(JAVA_CLASSPATH_OVERRIDE_COMMON)" ""
	COMMON_CP = /usr/local/share/java/$(JARFILE_COMMON):/usr/share/java/$(JARFILE_COMMON)
else
	COMMON_CP = $(JAVA_CLASSPATH_OVERRIDE_COMMON)/$(JARFILE_COMMON)
endif

JFLAGS = -g
JC = javac -classpath "$(CLASSPATH):$(JUL_CP):$(COMMON_CP):."
.SUFFIXES: .java .class
.java.class:
	$(JC) $(JFLAGS) $*.java

CLASSES = Hello.java FilterChangeListenerExample.java ApplicationContextExample.java

all: classes

classes: $(CLASSES:.java=.class)

.PHONY: clean
clean:
	$(RM) $(CLASSES:.java=.class)
