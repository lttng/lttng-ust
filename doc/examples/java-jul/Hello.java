/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2015 EfficiOS Inc., Alexandre Montplaisir <alexmonthy@efficios.com>
 * Copyright (C) 2013 David Goulet <dgoulet@efficios.com>
 */

import java.io.IOException;
import java.util.logging.Handler;
import java.util.logging.Logger;

import org.lttng.ust.agent.jul.LttngLogHandler;

/**
 * Example application using the LTTng-UST Java JUL agent.
 *
 * <p>
 * Basically all that is required is to instantiate a {@link LttngLogHandler}
 * and to attach it to a JUL {@link Logger}. Then use the Logger normally to log
 * messages, which will be sent to UST as trace events.
 * <p>
 * </p>
 * {@link Logger} names are used as event names on the UST side. This means that
 * by enabling/disabling certain events in the tracing session, you are
 * effectively enabling and disabling Loggers on the Java side. Note that this
 * applies only to {@link LttngLogHandler}'s. If other handlers are attached to
 * the Logger, those will continue logging events normally.
 * </p>
 *
 * <p>
 * To obtain LTTng trace events, you should run the following sequence of
 * commands:
 * </p>
 *
 * <ul>
 * <li>$ lttng create</li>
 * <li>$ lttng enable-event -j -a</li>
 * <li>$ lttng start</li>
 * <li>(run this program)</li>
 * <li>$ lttng stop</li>
 * <li>$ lttng view</li>
 * <li>$ lttng destroy</li>
 * </ul>
 *
 * @author Alexandre Montplaisir
 * @author David Goulet
 */
public class Hello {

	/** Class-wide JUL logger object */
	private static final Logger LOGGER = Logger.getLogger(Hello.class.getName());

	/**
	 * Application start
	 *
	 * @param args
	 *            Command-line arguments
	 * @throws IOException
	 *             If the required native libraries cannot be found. You may
	 *             have to specify "-Djava.library.path=..." on the "java"
	 *             command line.
	 */
	public static void main(String args[]) throws IOException {

		/* Instantiate a LTTngLogHandler object, and attach it to our logger */
		Handler lttngHandler = new LttngLogHandler();
		LOGGER.addHandler(lttngHandler);

		/* Log events using the JUL Logger created before. */
		LOGGER.info("Hello World, the answer is " + 42);
		LOGGER.info("Another info event");
		LOGGER.severe("A severe event");

		/* Cleanup */
		LOGGER.removeHandler(lttngHandler);
		lttngHandler.close();
	}
}
