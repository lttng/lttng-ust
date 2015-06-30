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

package org.lttng.ust.agent.jul;

import java.util.Enumeration;
import java.util.Iterator;
import java.util.Vector;

import java.util.logging.LogManager;
import java.util.logging.Logger;

import org.lttng.ust.agent.LogFrameworkSkeleton;

public class LTTngJUL extends LogFrameworkSkeleton {

	private LTTngLogHandler handler;
	private Boolean attached;

	public LTTngJUL(Boolean isRoot) {
		super();
		this.handler = new LTTngLogHandler(isRoot);
		this.attached = false;
	}

	@Override
	public Boolean enableLogger(String name) {
		if(!super.enableLogger(name)) {
			return false;
		}

		/* The first enable of any event triggers the attachment to the root logger */
		if (getEventCount() == 1 && !this.attached) {
			attachToRootLogger();
		}

		return true;
	}

	@Override
	public Boolean disableLogger(String name) {
		if(!super.disableLogger(name)) {
			return false;
		}

		/* Detach from the root logger when the event count reach zero */
		if (getEventCount() == 0 && this.attached) {
			detachFromRootLogger();
		}

		return true;
	}

	@Override
	public Iterator<String> listLoggers() {
		Vector<String> logs = new Vector<String>();
		for (Enumeration<String> loggers = LogManager.getLogManager().getLoggerNames(); loggers.hasMoreElements(); ) {
			String name = loggers.nextElement();
			/* Skip the root logger */
			if (name.equals("")) {
				continue;
			}

			logs.add(name);
		}

		return logs.iterator();
	}

	@Override
	public Boolean isRoot() {
		return handler.isRoot();
	}

	@Override
	public void reset() {
		super.reset();
		detachFromRootLogger();
	}

	private void attachToRootLogger() {
		if (this.attached) {
			return;
		}

		Logger rootLogger = LogManager.getLogManager().getLogger("");
		rootLogger.addHandler(this.handler);
		this.attached = true;
	}

	private void detachFromRootLogger() {
		if (!this.attached) {
			return;
		}

		Logger rootLogger = LogManager.getLogManager().getLogger("");
		rootLogger.removeHandler(this.handler);
		this.attached = false;
	}
}
