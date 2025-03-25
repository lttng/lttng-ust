/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2015 EfficiOS Inc.
 * Copyright (C) 2015 Alexandre Montplaisir <alexmonthy@efficios.com>
 * Copyright (C) 2014 Christian Babeux <christian.babeux@efficios.com>
 */

package org.lttng.ust.agent.log4j;

import java.io.IOException;
import java.util.Collection;
import java.util.Map;
import java.util.Map.Entry;
import java.util.concurrent.atomic.AtomicLong;

import org.apache.log4j.AppenderSkeleton;
import org.apache.log4j.spi.LoggingEvent;
import org.lttng.ust.agent.ILttngAgent;
import org.lttng.ust.agent.ILttngHandler;
import org.lttng.ust.agent.context.ContextInfoSerializer;

/**
 * LTTng-UST Log4j 1.x log handler.
 *
 * Applications can attach this appender to their
 * {@link org.apache.log4j.Logger} to have it generate UST events from logging
 * events received through the logger.
 *
 * It sends its events to UST via the JNI library "liblttng-ust-log4j-jni.so".
 * Make sure this library is available before using this appender.
 *
 * @author Alexandre Montplaisir
 * @author Christian Babeux
 */
public class LttngLogAppender extends AppenderSkeleton implements ILttngHandler {

	private static final String SHARED_OBJECT_NAME = "lttng-ust-log4j-jni";

	private static final String CONTEXT_OBJECT_NAME = "lttng-ust-context-jni";

	private final AtomicLong eventCount = new AtomicLong(0);

	private final ILttngAgent<LttngLogAppender> agent;


	/**
	 * Constructor
	 *
	 * @throws IOException
	 *             This handler requires the lttng-ust-log4j-jni.so native
	 *             library, through which it will send the trace events. This
	 *             exception is throw is this library cannot be found.
	 * @throws SecurityException
	 *             We will forward any SecurityExcepion that may be thrown when
	 *             trying to load the JNI library.
	 */
	public LttngLogAppender() throws IOException, SecurityException {
		super();
		/* Initialize LTTng UST tracer. */
		try {
			System.loadLibrary(CONTEXT_OBJECT_NAME); // $NON-NLS-1$
			System.loadLibrary(SHARED_OBJECT_NAME); // $NON-NLS-1$
		} catch (UnsatisfiedLinkError e) {
			throw new IOException(e);
		}

		/** Register to the relevant agent */
		agent = LttngLog4jAgent.getInstance();
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
	public boolean requiresLayout() {
		return false;
	}

	@Override
	protected void append(LoggingEvent event) {
		/*
		 * Check if the current message should be logged, according to the UST
		 * session settings.
		 */
		if (!agent.isEventEnabled(event.getLoggerName())) {
			return;
		}

		/*
		 * The line number returned from LocationInformation is a string. At
		 * least try to convert to a proper int.
		 */
		int line;
		try {
			String lineString = event.getLocationInformation().getLineNumber();
			line = Integer.parseInt(lineString);
		} catch (NumberFormatException n) {
			line = -1;
		}

		/* Retrieve all the requested context information we can find */
		Collection<Entry<String, Map<String, Integer>>> enabledContexts = agent.getEnabledAppContexts();
		ContextInfoSerializer.SerializedContexts contextInfo = ContextInfoSerializer.queryAndSerializeRequestedContexts(enabledContexts);

		eventCount.incrementAndGet();

		LttngLog4jApi.tracepointWithContext(event.getRenderedMessage(),
				event.getLoggerName(),
				event.getLocationInformation().getClassName(),
				event.getLocationInformation().getMethodName(),
				event.getLocationInformation().getFileName(),
				line,
				event.getTimeStamp(),
				event.getLevel().toInt(),
				event.getThreadName(),
				contextInfo.getEntriesArray(),
				contextInfo.getStringsArray());
	}

}
