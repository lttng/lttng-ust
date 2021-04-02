/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2016 EfficiOS Inc.
 * Copyright (C) 2016 Alexandre Montplaisir <alexmonthy@efficios.com>
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
