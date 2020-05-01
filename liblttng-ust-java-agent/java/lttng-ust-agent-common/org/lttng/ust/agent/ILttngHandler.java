/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2015 EfficiOS Inc.
 * Copyright (C) 2015 Alexandre Montplaisir <alexmonthy@efficios.com>
 */

package org.lttng.ust.agent;

/**
 * Simple interface to organize all LTTng log handlers under one type.
 *
 * @author Alexandre Montplaisir
 */
public interface ILttngHandler {

	/**
	 * Get the number of events logged by this handler since its inception.
	 * 
	 * @return The number of logged events
	 */
	long getEventCount();

	/**
	 * Close the log handler. Should be called once the application is done
	 * logging through it.
	 */
	void close();
}
