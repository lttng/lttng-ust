AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_builddir)/include

lib_LTLIBRARIES = liblttng-ust-jul-jni.la
liblttng_ust_jul_jni_la_SOURCES = lttng_ust_jul.c \
				  lttng_ust_jul.h

nodist_liblttng_ust_jul_jni_la_SOURCES = org_lttng_ust_agent_jul_LttngLogHandler.h

liblttng_ust_jul_jni_la_LIBADD = -lc -L$(top_builddir)/liblttng-ust/.libs -llttng-ust
