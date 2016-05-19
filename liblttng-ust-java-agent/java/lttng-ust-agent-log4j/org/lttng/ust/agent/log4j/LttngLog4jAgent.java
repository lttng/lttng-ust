/*
 * Copyright (C) 2015 - EfficiOS Inc., Alexandre Montplaisir <alexmonthy@efficios.com>
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License, version 2.1 only,
 * as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
 * for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

package org.lttng.ust.agent.log4j;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

import org.apache.log4j.Appender;
import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;
import org.lttng.ust.agent.AbstractLttngAgent;

/**
 * Agent implementation for using the Log4j logger, connecting to a root session
 * daemon.
 *
 * @author Alexandre Montplaisir
 */
class LttngLog4jAgent extends AbstractLttngAgent<LttngLogAppender> {

	private static LttngLog4jAgent instance = null;

	private LttngLog4jAgent() {
		super(Domain.LOG4J);
	}

	public static synchronized LttngLog4jAgent getInstance() {
		if (instance == null) {
			instance = new LttngLog4jAgent();
		}
		return instance;
	}

	@Override
	public Collection<String> listAvailableEvents() {
		List<String> ret = new ArrayList<String>();

		@SuppressWarnings("unchecked")
		List<Logger> loggers = Collections.list(LogManager.getCurrentLoggers());
		for (Logger logger : loggers) {
			if (logger == null) {
				continue;
			}

			/*
			 * Check if that logger has at least one LTTng log4j appender
			 * attached.
			 */
			if (hasLttngAppenderAttached(logger)) {
				ret.add(logger.getName());
			}
		}

		return ret;
	}

	private static boolean hasLttngAppenderAttached(Logger logger) {
		@SuppressWarnings("unchecked")
		List<Appender> appenders = Collections.list(logger.getAllAppenders());
		for (Appender appender : appenders) {
			if (appender instanceof LttngLogAppender) {
				return true;
			}
		}
		return false;
	}
}
