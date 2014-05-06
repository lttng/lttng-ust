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
import java.util.ArrayList;
import java.util.HashMap;

import org.lttng.ust.jul.LTTngUst;

/* Note: This is taken from the LTTng tools ABI. */
class LTTngLogLevelABI {
	/* Loglevel type. */
	public static final int LOGLEVEL_TYPE_ALL = 0;
	public static final int LOGLEVEL_TYPE_RANGE = 1;
	public static final int LOGLEVEL_TYPE_SINGLE = 2;
}

public class LTTngLogHandler extends Handler {
	/*
	 * Indicate if the enable all event has been seen and if yes logger that we
	 * enabled should use the loglevel/type below.
	 */
	public int logLevelUseAll = 0;
	public ArrayList<LTTngLogLevel> logLevelsAll =
		new ArrayList<LTTngLogLevel>();

	/* Am I a root Log Handler. */
	public int is_root = 0;

	public LogManager logManager;

	/* Indexed by name and corresponding LTTngEvent. */
	private HashMap<String, LTTngEvent> eventMap =
		new HashMap<String, LTTngEvent>();

	public LTTngLogHandler(LogManager logManager) {
		super();

		this.logManager = logManager;

		/* Initialize LTTng UST tracer. */
		LTTngUst.init();
	}

	/**
	 * Add event to handler hash map if new.
	 *
	 * @return 0 if it did not exist else 1.
	 */
	public int setEvent(LTTngEvent new_event) {
		LTTngEvent event;

		event = eventMap.get(new_event.name);
		if (event == null) {
			eventMap.put(new_event.name, new_event);
			/* Did not exists. */
			return 0;
		} else {
			/* Add new event loglevel to existing event. */
			event.logLevels.addAll(new_event.logLevels);
			/* Already exists. */
			return 1;
		}
	}

	/*
	 * Cleanup this handler state meaning put it back to a vanilla state.
	 */
	public void clear() {
		this.eventMap.clear();
		this.logLevelsAll.clear();
	}

	@Override
	public void close() throws SecurityException {}

	@Override
	public void flush() {}

	@Override
	public void publish(LogRecord record) {
		int fire_tp = 0, rec_log_level, ev_type, ev_log_level;
		LTTngEvent event;
		LTTngLogLevel lttngLogLevel;
		String logger_name = record.getLoggerName();

		/* Get back the event if any and check for loglevel. */
		event = eventMap.get(logger_name);
		if (event != null) {
			for (LTTngLogLevel ev_log : event.logLevels) {
				/* Get record and event log level. */
				rec_log_level = record.getLevel().intValue();
				ev_log_level = ev_log.level;

				switch (ev_log.type) {
				case LTTngLogLevelABI.LOGLEVEL_TYPE_RANGE:
					if (ev_log_level <= rec_log_level) {
						fire_tp = 1;
					}
					break;
				case LTTngLogLevelABI.LOGLEVEL_TYPE_SINGLE:
					if (ev_log_level == rec_log_level) {
						fire_tp = 1;
					}
					break;
				case LTTngLogLevelABI.LOGLEVEL_TYPE_ALL:
					fire_tp = 1;
					break;
				}

				/*
				 * If we match, stop right now else continue to the next
				 * loglevel contained in the event.
				 */
				if (fire_tp == 1) {
					break;
				}
			}
		} else {
			/* No loglevel attached thus fire tracepoint. */
			fire_tp = 1;
		}

		if (fire_tp == 0) {
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
