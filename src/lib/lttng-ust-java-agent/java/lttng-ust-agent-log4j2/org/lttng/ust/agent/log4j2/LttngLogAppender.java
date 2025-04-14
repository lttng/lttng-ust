/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2015-2022 EfficiOS Inc.
 * Copyright (C) 2015 Alexandre Montplaisir <alexmonthy@efficios.com>
 * Copyright (C) 2014 Christian Babeux <christian.babeux@efficios.com>
 */

package org.lttng.ust.agent.log4j2;

import java.io.IOException;
import java.util.Collection;
import java.util.Map;
import java.util.Map.Entry;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

import org.apache.logging.log4j.core.Appender;
import org.apache.logging.log4j.core.Core;
import org.apache.logging.log4j.core.Filter;
import org.apache.logging.log4j.core.LogEvent;
import org.apache.logging.log4j.core.appender.AbstractAppender;
import org.apache.logging.log4j.core.config.Property;
import org.apache.logging.log4j.core.config.plugins.Plugin;
import org.apache.logging.log4j.core.config.plugins.PluginAttribute;
import org.apache.logging.log4j.core.config.plugins.PluginElement;
import org.apache.logging.log4j.core.config.plugins.PluginFactory;
import org.apache.logging.log4j.message.Message;
import org.lttng.ust.agent.ILttngAgent.Domain;
import org.lttng.ust.agent.ILttngHandler;
import org.lttng.ust.agent.context.ContextInfoSerializer;

/**
 * LTTng-UST Log4j 2.x log handler.
 *
 * Applications can attach this appender to their
 * {@link org.apache.log4j.Logger} to have it generate UST events from logging
 * events received through the logger.
 *
 * It sends its events to UST via the JNI library "liblttng-ust-log4j-jni.so".
 * Make sure this library is available before using this appender.
 *
 */
@Plugin(name = LttngLogAppender.PLUGIN_NAME, category = Core.CATEGORY_NAME, elementType = Appender.ELEMENT_TYPE, printObject = false)
public final class LttngLogAppender extends AbstractAppender implements ILttngHandler {

	/**
	 * The name of the appender in the configuration.
	 */
	public static final String PLUGIN_NAME = "Lttng";

	private static final String SHARED_OBJECT_NAME = "lttng-ust-log4j-jni";

	private static final String CONTEXT_OBJECT_NAME = "lttng-ust-context-jni";

	/**
	 * Number of events logged (really sent through JNI) by this handler
	 */
	private final AtomicLong eventCount = new AtomicLong(0);

	private final LttngLog4j2Agent agent;

	/**
	 * Constructor
	 *
	 * @param name             The name of the Appender.
	 * @param domain           The LTTng-UST agent domain 'LOG4J' / 'LOG4J2'.
	 * @param filter           The Filter or null.
	 * @param ignoreExceptions If {@code "true"} exceptions encountered when
	 *                         appending events are logged; otherwise they are
	 *                         propagated to the caller.
	 *
	 * @throws IOException              This handler requires the
	 *                                  lttng-ust-log4j-jni.so native library,
	 *                                  through which it will send the trace events.
	 *                                  This exception is thrown if this library
	 *                                  cannot be found.
	 * @throws IllegalArgumentException If the provided domain is unsupported.
	 * @throws SecurityException        We will forward any SecurityExcepion that
	 *                                  may be thrown when trying to load the JNI
	 *                                  library.
	 */
	protected LttngLogAppender(String name, LttngLog4j2Agent.Domain domain, Filter filter, boolean ignoreExceptions)
			throws IOException, IllegalArgumentException, SecurityException {

		super(name, filter, null, ignoreExceptions, Property.EMPTY_ARRAY);

		/* Initialize LTTng UST tracer. */
		try {
			System.loadLibrary(CONTEXT_OBJECT_NAME); // $NON-NLS-1$
			System.loadLibrary(SHARED_OBJECT_NAME); // $NON-NLS-1$
		} catch (UnsatisfiedLinkError e) {
			throw new IOException(e);
		}

		/* Register to the relevant agent. */
		if (domain == LttngLog4j2Agent.Domain.LOG4J) {
			agent = LttngLog4j2Agent.getLog4j1Instance();
		} else if (domain == LttngLog4j2Agent.Domain.LOG4J2) {
			agent = LttngLog4j2Agent.getLog4j2Instance();
		} else {
			throw new IllegalArgumentException("Unsupported domain '" + domain + "'");
		}

		agent.registerHandler(this);
	}

	/**
	 * Create an LttngLogAppender.
	 *
	 * @param name             The name of the Appender, null returns null.
	 * @param domain           The LTTng-UST agent domain 'LOG4J' / 'LOG4J2'.
	 * @param ignoreExceptions If {@code "true"} (default) exceptions encountered
	 *                         when appending events are logged; otherwise they are
	 *                         propagated to the caller.
	 * @param filter           The Filter or null.
	 *
	 * @return A new LttngLogAppender, null if the name was null or the domain is
	 *         null or invalid.
	 */
	@PluginFactory
	public static LttngLogAppender createAppender(@PluginAttribute("name") String name,
			@PluginAttribute("domain") String domain, @PluginAttribute("ignoreExceptions") Boolean ignoreExceptions,
			@PluginElement("Filters") Filter filter) {

		if (name == null) {
			LOGGER.error("No name provided for LttngLogAppender");
			return null;
		}

		if (domain == null) {
			LOGGER.error("No domain provided for LttngLogAppender");
			return null;
		}

		if (ignoreExceptions == null) {
			ignoreExceptions = true;
		}

		/* Parse the domain string */
		LttngLog4j2Agent.Domain parsedDomain;
		try {
			parsedDomain = LttngLog4j2Agent.Domain.valueOf(domain.toUpperCase());
		} catch (IllegalArgumentException e) {
			LOGGER.error("Invalid domain '{}' for LttngLogAppender", domain);
			return null;
		}

		/* Create the appender and handle the possible failures. */
		LttngLogAppender newAppender;
		try {
			newAppender = new LttngLogAppender(name, parsedDomain, filter, ignoreExceptions);
		} catch (IllegalArgumentException e) {
			LOGGER.error("Invalid domain '{}' for LttngLogAppender", parsedDomain);
			newAppender = null;
		} catch (SecurityException e) {
			LOGGER.error("Security error trying to load '{}' JNI library for LttngLogAppender", SHARED_OBJECT_NAME);
			newAppender = null;
		} catch (IOException e) {
			LOGGER.error("Failed to load '{}' JNI library for LttngLogAppender", SHARED_OBJECT_NAME);
			newAppender = null;
		}

		return newAppender;
	}

	@Override
	public synchronized void close() {
		agent.unregisterHandler(this);
	}

	@Override
	public void stop() {
		close();
		super.stop();

		getStatusLogger().debug("Appender Lttng stopped");
	}

	@Override
	public boolean stop(final long timeout, final TimeUnit timeUnit) {
		close();
		boolean status = super.stop(timeout, timeUnit);

		getStatusLogger().debug("Appender Lttng stopped with status " + status);

		return status;
	}

	/**
	 * Get the number of events logged by this handler so far. This means the number
	 * of events actually sent through JNI to UST.
	 *
	 * @return The number of events logged so far
	 */
	@Override
	public long getEventCount() {
		return eventCount.get();
	}

	@Override
	public void append(LogEvent event) {
		/*
		 * Check if the current message should be logged, according to the UST session
		 * settings.
		 */
		String loggername = event.getLoggerName();
		if (loggername == null || !agent.isEventEnabled(loggername)) {
			return;
		}

		/*
		 * Default value if the Message is null.
		 */
		String message = "";

		Message eventMessage = event.getMessage();
		if (eventMessage != null) {
			message = eventMessage.getFormattedMessage();
		}

		/*
		 * Default values if the StackTraceElement is null.
		 */
		String classname = "";
		String methodname = "";
		String filename = "";
		int line = -1;

		StackTraceElement ste = event.getSource();
		if (ste != null) {
			classname = ste.getClassName();
			methodname = ste.getMethodName();
			filename = ste.getFileName();
			line = ste.getLineNumber();
		}

		/* Retrieve all the requested context information we can find. */
		Collection<Entry<String, Map<String, Integer>>> enabledContexts = agent.getEnabledAppContexts();
		ContextInfoSerializer.SerializedContexts contextInfo = ContextInfoSerializer
				.queryAndSerializeRequestedContexts(enabledContexts);

		eventCount.incrementAndGet();

		LttngLog4j2Api.tracepointWithContext(message, loggername, classname, methodname, filename, line,
				event.getTimeMillis(), event.getLevel().intLevel(), event.getThreadName(),
				contextInfo.getEntriesArray(), contextInfo.getStringsArray(), agent.getDomain() == Domain.LOG4J);
	}
}
