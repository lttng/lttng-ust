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

import java.util.Map;
import java.util.HashMap;
import java.util.Iterator;

public abstract class LogFrameworkSkeleton implements LogFramework {

	/* A map of event name and reference count */
	private Map<String, Integer> enabledLoggers;

	public LogFrameworkSkeleton() {
		this.enabledLoggers = new HashMap<String, Integer>();
	}

	@Override
	public Boolean enableLogger(String name) {
		if (name == null) {
			return false;
		}

		if (enabledLoggers.containsKey(name)) {
			/* Event is already enabled, simply increment its refcount */
			Integer refcount = enabledLoggers.get(name);
			refcount++;
			Integer oldval = enabledLoggers.put(name, refcount);
			assert (oldval != null);
		} else {
			/* Event was not enabled, init refcount to 1 */
			Integer oldval = enabledLoggers.put(name, 1);
			assert (oldval == null);
		}

		return true;
	}

	@Override
	public Boolean disableLogger(String name) {
		if (name == null) {
			return false;
		}

		if (!enabledLoggers.containsKey(name)) {
			/* Event was never enabled, abort */
			return false;
		}

		/* Event was previously enabled, simply decrement its refcount */
		Integer refcount = enabledLoggers.get(name);
		refcount--;
		assert (refcount >= 0);

		if (refcount == 0) {
			/* Event is not used anymore, remove it from the map */
			Integer oldval = enabledLoggers.remove(name);
			assert (oldval != null);
		}

		return true;
	}

	@Override
	public abstract Iterator<String> listLoggers();

	@Override
	public abstract Boolean isRoot();

	@Override
	public void reset() {
		enabledLoggers.clear();
	}

	protected Integer getEventCount() {
		return enabledLoggers.size();
	}
}
