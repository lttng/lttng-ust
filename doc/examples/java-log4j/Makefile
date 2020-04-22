#
# Copyright (C) 2014 - Christian Babeux <christian.babeux@efficios.com>
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

# Required JAR files for Log4j
JARFILE_LOG4J=lttng-ust-agent-log4j.jar
JARFILE_COMMON=lttng-ust-agent-common.jar

# If system classpath is empty, try to guess log4j location
ifeq "$(CLASSPATH)" ""
	CLASSPATH=/usr/local/share/java/log4j.jar:/usr/share/java/log4j.jar
endif

# Check if the top level makefile overrides the Log4j Jar file's path.
ifeq "$(JAVA_CLASSPATH_OVERRIDE_LOG4J)" ""
	CLASSPATH:=$(CLASSPATH):/usr/local/share/java/$(JARFILE_LOG4J):/usr/share/java/$(JARFILE_LOG4J)
else
	CLASSPATH:=$(CLASSPATH):$(JAVA_CLASSPATH_OVERRIDE_LOG4J)/$(JARFILE_LOG4J)
endif

# Check if the top level makefile overrides the Common Jar file's path.
ifeq "$(JAVA_CLASSPATH_OVERRIDE_COMMON)" ""
	CLASSPATH:=$(CLASSPATH):/usr/local/share/java/$(JARFILE_COMMON):/usr/share/java/$(JARFILE_COMMON)
else
	CLASSPATH:=$(CLASSPATH):$(JAVA_CLASSPATH_OVERRIDE_COMMON)/$(JARFILE_COMMON)
endif

JFLAGS = -g
JC = javac -classpath "$(CLASSPATH):."
.SUFFIXES: .java .class
.java.class:
	$(JC) $(JFLAGS) $*.java

CLASSES = Hello.java

all: classes

classes: $(CLASSES:.java=.class)

.PHONY: clean
clean:
	$(RM) *.class
