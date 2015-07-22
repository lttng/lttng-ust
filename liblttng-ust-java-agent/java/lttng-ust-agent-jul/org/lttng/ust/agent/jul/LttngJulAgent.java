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

package org.lttng.ust.agent.jul;

import org.lttng.ust.agent.AbstractLttngAgent;

/**
 * Agent implementation for tracing from JUL loggers.
 *
 * @author Alexandre Montplaisir
 */
class LttngJulAgent extends AbstractLttngAgent<LttngLogHandler> {

	private static LttngJulAgent instance = null;

	private LttngJulAgent() {
		super(Domain.JUL);
	}

	public static synchronized LttngJulAgent getInstance() {
		if (instance == null) {
			instance = new LttngJulAgent();
		}
		return instance;
	}

}
