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

package org.lttng.ust.agent.log4j;

import java.util.Enumeration;
import java.util.Iterator;
import java.util.Vector;

import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;

import org.lttng.ust.agent.LogFrameworkSkeleton;

public class LTTngLog4j extends LogFrameworkSkeleton {

	private LTTngLogAppender appender;
	private Boolean attached;

	public LTTngLog4j(Boolean isRoot) {
		super();
		this.appender = new LTTngLogAppender(isRoot);
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

		/* Detach from the root logger when the event counts reach zero */
		if (getEventCount() == 0 && this.attached) {
			detachFromRootLogger();
		}

		return true;
	}

	@Override
	public Iterator<String> listLoggers() {
		Vector<String> logs = new Vector<String>();
		for (Enumeration loggers = LogManager.getCurrentLoggers(); loggers.hasMoreElements(); ) {
			Logger logger = (Logger) loggers.nextElement();
			String name = logger.getName();
			logs.add(name);
		}

		return logs.iterator();
	}

	@Override
	public Boolean isRoot() {
		return appender.isRoot();
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

		Logger logger = Logger.getRootLogger();
		logger.addAppender(this.appender);
		this.attached = true;
	}

	private void detachFromRootLogger() {
		if (!this.attached) {
			return;
		}

		Logger logger = Logger.getRootLogger();
		logger.removeAppender(this.appender);
		this.attached = false;
	}
}
