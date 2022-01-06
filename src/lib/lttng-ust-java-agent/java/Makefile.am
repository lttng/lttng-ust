# SPDX-License-Identifier: LGPL-2.1-only

SUBDIRS = lttng-ust-agent-common lttng-ust-agent-all

if ENABLE_JAVA_AGENT_WITH_JUL
SUBDIRS += lttng-ust-agent-jul
endif

if ENABLE_JAVA_AGENT_WITH_LOG4J
SUBDIRS += lttng-ust-agent-log4j
endif

if ENABLE_JAVA_AGENT_WITH_LOG4J2
SUBDIRS += lttng-ust-agent-log4j2
endif
