AM_CPPFLAGS = -I$(top_srcdir)/include
lib_LTLIBRARIES = liblttng-ust-log4j-jni.la
liblttng_ust_log4j_jni_la_SOURCES = lttng_ust_log4j.c \
				  lttng_ust_log4j.h

nodist_liblttng_ust_log4j_jni_la_SOURCES = org_lttng_ust_agent_log4j_LTTngLogAppender.h

liblttng_ust_log4j_jni_la_LIBADD = -lc -L$(top_builddir)/liblttng-ust/.libs -llttng-ust
