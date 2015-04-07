/*
 * Copyright (C) 2014 - Christian Babeux <christian.babeux@efficios.com>
 *
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

import java.util.Iterator;

interface LogFramework {
	Boolean enableLogger(String name);
	Boolean disableLogger(String name);
	Iterator<String> listLoggers();
	Boolean isRoot();
	void reset();
	void setEnableRefCountDecrement(boolean enableRefCountDecrement);
}
