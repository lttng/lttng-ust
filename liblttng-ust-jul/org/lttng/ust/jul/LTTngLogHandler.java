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

public class LTTngLogHandler extends Handler {
	/* Am I a root Log Handler. */
	public int is_root = 0;
	public int refcount = 0;

	public LogManager logManager;

	/* Logger object attached to this handler that can trigger a tracepoint. */
	public Map<String, LTTngEvent> enabledEvents =
		Collections.synchronizedMap(new HashMap<String, LTTngEvent>());

	/* Constructor */
	public LTTngLogHandler(LogManager logManager) {
		super();

		this.logManager = logManager;

		/* Initialize LTTng UST tracer. */
		LTTngUst.init();
	}

	/*
	 * Cleanup this handler state meaning put it back to a vanilla state.
	 */
	public void clear() {
		this.enabledEvents.clear();
	}

	@Override
	public void close() throws SecurityException {}

	@Override
	public void flush() {}

	@Override
	public void publish(LogRecord record) {
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
