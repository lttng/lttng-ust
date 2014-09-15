JAVAROOT = .

jarfile = liblttng-ust-agent.jar
jarfile_old = liblttng-ust-jul.jar
jardir = $(datadir)/java
juljniout = ../jni/jul
log4jjniout = ../jni/log4j
pkgpath = org/lttng/ust/agent
pkgpath_old = org/lttng/ust/jul
dist_noinst_JAVA = $(pkgpath)/LTTngAgent.java \
		   $(pkgpath)/LTTngSessiondCmd2_6.java \
		   $(pkgpath)/LTTngTCPSessiondClient.java \
		   $(pkgpath)/LogFramework.java \
		   $(pkgpath)/LogFrameworkSkeleton.java \
		   $(pkgpath)/jul/LTTngJUL.java \
		   $(pkgpath)/jul/LTTngLogHandler.java \
		   $(pkgpath_old)/LTTngAgent.java

jar_DATA = $(jarfile) $(jarfile_old)

stamp =
classes = $(pkgpath)/*.class

if BUILD_JAVA_AGENT_WITH_JUL
dist_noinst_JAVA += $(pkgpath)/jul/LTTngJUL.java \
		    $(pkgpath)/jul/LTTngLogHandler.java
stamp += jul-jni-header.stamp
classes += $(pkgpath)/jul/*.class
endif

if BUILD_JAVA_AGENT_WITH_LOG4J
dist_noinst_JAVA += $(pkgpath)/log4j/LTTngLog4j.java \
		    $(pkgpath)/log4j/LTTngLogAppender.java
stamp += log4j-jni-header.stamp
classes += $(pkgpath)/log4j/*.class
endif

$(jarfile): classnoinst.stamp
	$(JAR) cf $(JARFLAGS) $@ $(classes)

$(jarfile_old): classnoinst.stamp
	$(JAR) cf $(JARFLAGS) $@ $(pkgpath)/*.class \
	$(pkgpath)/jul/*.class $(pkgpath_old)/*.class

jul-jni-header.stamp: $(dist_noinst_JAVA)
	$(JAVAH) -cp $(CLASSPATH):. -d $(juljniout) $(JAVAHFLAGS) org.lttng.ust.agent.jul.LTTngLogHandler && \
	echo "JUL JNI header generated" > jul-jni-header.stamp

log4j-jni-header.stamp: $(dist_noinst_JAVA)
	$(JAVAH) -cp $(CLASSPATH):. -d $(log4jjniout) $(JAVAHFLAGS) org.lttng.ust.agent.log4j.LTTngLogAppender && \
	echo "Log4j JNI header generated" > log4j-jni-header.stamp

all-local: $(stamp)

CLEANFILES = $(jarfile) $(jarfile_old) $(pkgpath)/*.class $(pkgpath_old)/*.class $(pkgpath)/jul/*.class \
	$(pkgpath)/log4j/*.class jul-jni-header.stamp log4j-jni-header.stamp \
	$(juljniout)/org_lttng_ust_agent_jul_LTTngLogHandler.h \
	$(log4jjniout)/org_lttng_ust_agent_log4j_LTTngLogAppender.h
