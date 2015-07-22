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

}
