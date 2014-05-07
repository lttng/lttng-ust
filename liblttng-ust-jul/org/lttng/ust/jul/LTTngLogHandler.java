/*
 * Copyright (C) 2013 - David Goulet <dgoulet@efficios.com>
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
import java.util.logging.Handler;
import java.util.logging.LogRecord;
import java.util.logging.LogManager;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.lttng.ust.jul.LTTngUst;

class LTTngLogger {
	/*
	 * The log handler is attached to the logger when the reference count is
	 * nonzero. Each event referring to a logger holds a reference to that
	 * logger. If down to 0, this object is removed from the handler.
	 */
	public int refcount;
	public String name;
	Logger logger;

	public LTTngLogger(String name, Logger logger) {
		this.name = name;
		this.refcount = 0;
		this.logger = logger;
	}

	public void attach(LTTngLogHandler handler) {
		this.logger.addHandler(handler);
	}

	public void detach(LTTngLogHandler handler) {
		this.logger.removeHandler(handler);
	}
}

public class LTTngLogHandler extends Handler {
	/* Am I a root Log Handler. */
	public int is_root = 0;

	public LogManager logManager;

	/* Logger object attached to this handler that can trigger a tracepoint. */
	private Map<String, LTTngLogger> loggerMap =
		Collections.synchronizedMap(new HashMap<String, LTTngLogger>());

	/* Constructor */
	public LTTngLogHandler(LogManager logManager) {
		super();

		this.logManager = logManager;

		/* Initialize LTTng UST tracer. */
		LTTngUst.init();
	}

	/*
	 * Return true if the logger is enabled and attached. Else, if not found,
	 * return false.
	 */
	public boolean exists(String name) {
		if (loggerMap.get(name) != null) {
			return true;
		} else {
			return false;
		}
	}

	/*
	 * Attach an event to this handler. If no logger object exists, one is
	 * created else the refcount is incremented.
	 */
	public void attachEvent(LTTngEvent event) {
		Logger logger;
		LTTngLogger lttngLogger;

		/* Does the logger actually exist. */
		logger = this.logManager.getLogger(event.name);
		if (logger == null) {
			/* Stop attach right now. */
			return;
		}

		lttngLogger = loggerMap.get(event.name);
		if (lttngLogger == null) {
			lttngLogger = new LTTngLogger(event.name, logger);

			/* Attach the handler to the logger and add is to the map. */
			lttngLogger.attach(this);
			lttngLogger.refcount = 1;
			loggerMap.put(lttngLogger.name, lttngLogger);
		} else {
			lttngLogger.refcount += 1;
		}
	}

	/*
	 * Dettach an event from this handler. If the refcount goes down to 0, the
	 * logger object is removed thus not attached anymore.
	 */
	public void detachEvent(LTTngEvent event) {
		LTTngLogger logger;

		logger = loggerMap.get(event.name);
		if (logger != null) {
			logger.refcount -= 1;
			if (logger.refcount == 0) {
				/* Dettach from handler since no more event is associated. */
				logger.detach(this);
				loggerMap.remove(logger);
			}
		}
	}

	/*
	 * Cleanup this handler state meaning put it back to a vanilla state.
	 */
	public void clear() {
		this.loggerMap.clear();
	}

	@Override
	public void close() throws SecurityException {}

	@Override
	public void flush() {}

	@Override
	public void publish(LogRecord record) {
		LTTngLogger logger;

		logger = loggerMap.get(record.getLoggerName());
		if (logger == null) {
			/* Ignore and don't fire TP. */
			return;
		}

		/*
		 * Specific tracepoing designed for JUL events. The source class of the
		 * caller is used for the event name, the raw message is taken, the
		 * loglevel of the record and the thread ID.
		 */
		if (this.is_root == 1) {
			LTTngUst.tracepointS(record.getMessage(),
					record.getLoggerName(), record.getSourceClassName(),
					record.getSourceMethodName(), record.getMillis(),
					record.getLevel().intValue(), record.getThreadID());
		} else {
			LTTngUst.tracepointU(record.getMessage(),
					record.getLoggerName(), record.getSourceClassName(),
					record.getSourceMethodName(), record.getMillis(),
					record.getLevel().intValue(), record.getThreadID());
		}
	}
}
