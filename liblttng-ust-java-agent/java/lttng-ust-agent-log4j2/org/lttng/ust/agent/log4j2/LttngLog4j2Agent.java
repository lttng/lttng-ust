/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2015-2022 EfficiOS Inc.
 * Copyright (C) 2015 Alexandre Montplaisir <alexmonthy@efficios.com>
 */

package org.lttng.ust.agent.log4j2;

import java.util.Collection;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.Appender;
import org.apache.logging.log4j.core.Logger;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.impl.Log4jContextFactory;
import org.apache.logging.log4j.core.selector.ContextSelector;
import org.apache.logging.log4j.spi.LoggerContextFactory;
import org.apache.logging.log4j.status.StatusLogger;
import org.lttng.ust.agent.AbstractLttngAgent;

/**
 * Agent implementation for Log4j 2.x.
 */
class LttngLog4j2Agent extends AbstractLttngAgent<LttngLogAppender> {

	private static LttngLog4j2Agent instance = null;

	private LttngLog4j2Agent() {
		super(Domain.LOG4J);
	}

	public static synchronized LttngLog4j2Agent getInstance() {
		if (instance == null) {
			instance = new LttngLog4j2Agent();
		}
		return instance;
	}

	@Override
	public Collection<String> listAvailableEvents() {
		Set<String> eventNames = new TreeSet<>();

		LoggerContextFactory contextFactory = LogManager.getFactory();
		if (!(contextFactory instanceof Log4jContextFactory)) {
			/* Using a custom ContextFactory is not supported. */
			StatusLogger.getLogger().error("Can't list events with custom ContextFactory");
			return eventNames;
		}

		ContextSelector selector = ((Log4jContextFactory) contextFactory).getSelector();

		for (LoggerContext logContext : selector.getLoggerContexts()) {
			Collection<? extends Logger> loggers = logContext.getLoggers();
			for (Logger logger : loggers) {
				/*
				 * Check if that logger has at least one LTTng log4j appender attached.
				 */
				if (hasLttngAppenderAttached(logger)) {
					eventNames.add(logger.getName());
				}
			}
		}
		return eventNames;
	}

	/*
	 * Check if a logger has an LttngLogAppender attached.
	 *
	 * @param logger the Logger to check, null returns false
	 * @return true if the logger or its parent has at least one LttngLogAppender attached
	 */
	private static boolean hasLttngAppenderAttached(Logger logger) {

		if (logger == null) {
			return false;
		}

		/*
		 * Check all the appenders associated with the logger and return true if one of
		 * them is an LttngLogAppender.
		 */
		Map<String, Appender> appenders = logger.getAppenders();
		for (Map.Entry<String, Appender> appender : appenders.entrySet()) {
			if (appender.getValue() instanceof LttngLogAppender) {
				return true;
			}
		}

		/*
		 * A parent logger, if any, may be connected to an LTTng handler. In this case,
		 * we will want to include this child logger in the output, since it will be
		 * accessible by LTTng.
		 *
		 * Despite the doc, getParent can return null based on the implementation as of
		 * log4j 2.17.1.
		 *
		 * The getParent function is there as a backward compat for 1.x. It is not clear
		 * in which context it should be used. The cost of doing the lookup is minimal
		 * and mimics what was done for the 1.x agent.
		 */
		return hasLttngAppenderAttached(logger.getParent());

	}
}
