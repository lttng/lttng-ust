# SPDX-License-Identifier: LGPL-2.1-only
#
# Copyright (C) 2014 Christian Babeux <christian.babeux@efficios.com>
#
# This Makefile is not using automake so that users may see how to build a
# program with tracepoint provider probes as stand-alone shared objects.
#
# This makefile is purposefully kept simple to support GNU and BSD make.
#

# Required JAR files for Log4j 2.x
JARFILE_LOG4J2=lttng-ust-agent-log4j2.jar
JARFILE_COMMON=lttng-ust-agent-common.jar

# If system classpath is empty, try to guess log4j location
ifeq "$(CLASSPATH)" ""
	CLASSPATH=/usr/local/share/java/log4j.jar:/usr/share/java/log4j.jar
endif

# Check if the top level makefile overrides the Log4j Jar file's path.
ifeq "$(JAVA_CLASSPATH_OVERRIDE_LOG4J2)" ""
	LOG4J2_CP = /usr/local/share/java/$(JARFILE_LOG4J2):/usr/share/java/$(JARFILE_LOG4J2)
else
	LOG4J2_CP = $(JAVA_CLASSPATH_OVERRIDE_LOG4J2)/$(JARFILE_LOG4J2)
endif

# Check if the top level makefile overrides the Common Jar file's path.
ifeq "$(JAVA_CLASSPATH_OVERRIDE_COMMON)" ""
	COMMON_CP = /usr/local/share/java/$(JARFILE_COMMON):/usr/share/java/$(JARFILE_COMMON)
else
	COMMON_CP = $(JAVA_CLASSPATH_OVERRIDE_COMMON)/$(JARFILE_COMMON)
endif

JFLAGS = -g
JC = javac -classpath "$(CLASSPATH):$(LOG4J2_CP):$(COMMON_CP):."
.SUFFIXES: .java .class
.java.class:
	$(JC) $(JFLAGS) $*.java

CLASSES = HelloLog4j2Ctx.java

all: classes

classes: $(CLASSES:.java=.class)

.PHONY: clean
clean:
	$(RM) $(CLASSES:.java=.class)
