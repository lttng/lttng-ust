/*
 * Copyright (C) 2015 - EfficiOS Inc., Alexandre Montplaisir <alexmonthy@efficios.com>
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

import java.io.IOException;
import java.util.Collection;
import java.util.Map;
import java.util.Map.Entry;
import java.util.concurrent.atomic.AtomicLong;
import java.util.logging.Formatter;
import java.util.logging.Handler;
import java.util.logging.LogRecord;

import org.lttng.ust.agent.ILttngAgent;
import org.lttng.ust.agent.ILttngHandler;
import org.lttng.ust.agent.context.ContextInfoSerializer;

/**
 * LTTng-UST JUL log handler.
 *
 * Applications can attach this handler to their
 * {@link java.util.logging.Logger} to have it generate UST events from logging
 * events received through the logger.
 *
 * It sends its events to UST via the JNI library "liblttng-ust-jul-jni.so".
 * Make sure this library is available before using this handler.
 *
 * @author Alexandre Montplaisir
 * @author David Goulet
 */
public class LttngLogHandler extends Handler implements ILttngHandler {

	private static final String SHARED_OBJECT_NAME = "lttng-ust-jul-jni";

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

	private final ILttngAgent<LttngLogHandler> agent;

	/** Number of events logged (really sent through JNI) by this handler */
	private final AtomicLong eventCount = new AtomicLong(0);

	/**
	 * Constructor
	 *
	 * @throws IOException
	 *             This handler requires the lttng-ust-jul-jni.so native
	 *             library, through which it will send the trace events. This
	 *             exception is throw is this library cannot be found.
	 * @throws SecurityException
	 *             We will forward any SecurityExcepion that may be thrown when
	 *             trying to load the JNI library.
	 */
	public LttngLogHandler() throws IOException, SecurityException {
		super();
		/* Initialize LTTng UST tracer. */
		try {
			System.loadLibrary(SHARED_OBJECT_NAME); //$NON-NLS-1$
		} catch (UnsatisfiedLinkError e) {
			throw new IOException(e);
		}

		/** Register to the relevant agent */
		agent = LttngJulAgent.getInstance();
		agent.registerHandler(this);
	}

	@Override
	public synchronized void close() {
		agent.unregisterHandler(this);
	}

	/**
	 * Get the number of events logged by this handler so far. This means the
	 * number of events actually sent through JNI to UST.
	 *
	 * @return The number of events logged so far
	 */
	@Override
	public long getEventCount() {
		return eventCount.get();
	}

	@Override
	public void flush() {
	}

	@Override
	public void publish(LogRecord record) {
		/*
		 * Check if the current message should be logged, according to the UST
		 * session settings.
		 */
		if (!agent.isEventEnabled(record.getLoggerName())) {
			return;
		}

		String formattedMessage = FORMATTER.formatMessage(record);

		/* Retrieve all the requested context information we can find */
		Collection<Entry<String, Map<String, Integer>>> enabledContexts = agent.getEnabledAppContexts();
		ContextInfoSerializer.SerializedContexts contextInfo = ContextInfoSerializer.queryAndSerializeRequestedContexts(enabledContexts);

		eventCount.incrementAndGet();

		/*
		 * Specific tracepoint designed for JUL events. The source class of the
		 * caller is used for the event name, the raw message is taken, the
		 * loglevel of the record and the thread ID.
		 */
		LttngJulApi.tracepointWithContext(formattedMessage,
				record.getLoggerName(),
				record.getSourceClassName(),
				record.getSourceMethodName(),
				record.getMillis(),
				record.getLevel().intValue(),
				record.getThreadID(),
				contextInfo.getEntriesArray(),
				contextInfo.getStringsArray());
	}

}
