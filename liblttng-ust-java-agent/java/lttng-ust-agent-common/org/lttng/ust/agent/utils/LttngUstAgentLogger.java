/*
 * Copyright (C) 2016 - EfficiOS Inc., Alexandre Montplaisir <alexmonthy@efficios.com>
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

package org.lttng.ust.agent.utils;

/**
 * Logging infrastructure for the lttng-ust Java agent. It prints log messages
 * to stderr but only when the environment variable LTTNG_UST_DEBUG is defined.
 *
 * @author Alexandre Montplaisir
 */
public class LttngUstAgentLogger {

	private static final String ENV_VAR_NAME = "LTTNG_UST_DEBUG";
	private static final boolean LOGGING_ENABLED = (System.getenv(ENV_VAR_NAME) == null ? false : true);

	/**
	 * Log event. Will be printed to stderr if the environment variable
	 * "LTTNG_UST_DEBUG" is defined.
	 *
	 * @param c
	 *            The class logging the message (should normally be called with
	 *            {@link #getClass()}).
	 * @param message
	 *            The message to print
	 */
	public static void log(Class<?> c, String message) {
		if (LOGGING_ENABLED) {
			System.err.println(c.getSimpleName() + ": " + message);
		}
	}
}
