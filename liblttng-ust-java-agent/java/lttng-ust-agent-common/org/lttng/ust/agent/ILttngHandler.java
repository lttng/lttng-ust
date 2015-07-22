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
