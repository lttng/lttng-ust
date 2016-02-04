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

package org.lttng.ust.agent.jul;

import java.lang.String;

import java.util.logging.Formatter;
import java.util.logging.Handler;
import java.util.logging.LogRecord;

class LTTngLogHandler extends Handler {

	/**
	 * Dummy Formatter object, so we can use its
	 * {@link Formatter#formatMessage(LogRecord)} method.
	 */
	private static final Formatter FORMATTER = new Formatter() {
		@Override
		public String format(LogRecord record) {
			throw new UnsupportedOperationException();
		}
	};

	private final Boolean isRoot;

	public LTTngLogHandler(Boolean isRoot) {
		super();
		this.isRoot = isRoot;
		/* Initialize LTTng UST tracer. */
		try {
			System.loadLibrary("lttng-ust-jul-jni"); //$NON-NLS-1$
		} catch (SecurityException e) {
			e.printStackTrace();
		} catch (UnsatisfiedLinkError e) {
			e.printStackTrace();
		} catch (NullPointerException e) {
			/* Should never happen */
			e.printStackTrace();
		}
	}

	public Boolean isRoot() {
		return this.isRoot;
	}

	@Override
	public void close() throws SecurityException {}

	@Override
	public void flush() {}

	@Override
	public void publish(LogRecord record) {
		String formattedMessage = FORMATTER.formatMessage(record);

		/*
		 * Specific tracepoint designed for JUL events. The source class of the
		 * caller is used for the event name, the raw message is taken, the
		 * loglevel of the record and the thread ID.
		 */
		if (this.isRoot) {
			tracepointS(formattedMessage,
				    record.getLoggerName(), record.getSourceClassName(),
				    record.getSourceMethodName(), record.getMillis(),
				    record.getLevel().intValue(), record.getThreadID());
		} else {
			tracepointU(formattedMessage,
				    record.getLoggerName(), record.getSourceClassName(),
				    record.getSourceMethodName(), record.getMillis(),
				    record.getLevel().intValue(), record.getThreadID());
		}
	}

	/* Use for a user session daemon. */
	private native void tracepointU(String msg,
			String logger_name,
			String class_name,
			String method_name,
			long millis,
			int log_level,
			int thread_id);

	/* Use for a root session daemon. */
	private native void tracepointS(String msg,
			String logger_name,
			String class_name,
			String method_name,
			long millis,
			int log_level,
			int thread_id);
}
