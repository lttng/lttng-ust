/*
 * Copyright (C) 2014 - David Goulet <dgoulet@efficios.com>
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

package org.lttng.ust.jul;

import java.lang.String;

import org.lttng.ust.jul.LTTngUst;

class LTTngLogLevel {
	/* This level is a JUL int level value. */
	public int level;
	public int type;

	public LTTngLogLevel(int level, int type) {
		this.type = type;
		this.level = level;
	}
}

public class LTTngEvent {
	/* Name of the event. */
	public String name;
	public LTTngLogLevel logLevel;

	public LTTngEvent(String name, int loglevel, int loglevel_type) {
		this.name = name;
		this.logLevel = new LTTngLogLevel(loglevel, loglevel_type);
	}
}
