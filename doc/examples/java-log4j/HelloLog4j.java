/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2015 EfficiOS Inc.
 * Copyright (C) 2015 Alexandre Montplaisir <alexmonthy@efficios.com>
 * Copyright (C) 2014 Christian Babeux <christian.babeux@efficios.com>
 */

import java.io.IOException;

import org.apache.log4j.Appender;
import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.Logger;
import org.apache.log4j.Level;
import org.lttng.ust.agent.log4j.LttngLogAppender;

/**
 * Example application using the LTTng-UST Java log4j agent.
 *
 * <p>
 * To obtain LTTng trace events, you should run the following sequence of
 * commands:
 * </p>
 *
 * <ul>
 * <li>$ lttng create</li>
 * <li>$ lttng enable-event -l -a</li>
 * <li>$ lttng start</li>
 * <li>(run this program)</li>
 * <li>$ lttng stop</li>
 * <li>$ lttng view</li>
 * <li>$ lttng destroy</li>
 * </ul>
 *
 * @author Alexandre Montplaisir
 * @author Christian Babeux
 */
public class HelloLog4j {

	private static final Logger HELLO_LOG = Logger.getLogger(HelloLog4j.class);

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

		/*
		 * Set lowest level to make sure all event levels are logged.
		 * Any jar can override the default log4j rootLogger level
		 * and a logger with no explicit level defaults to the non-null
		 * parent level. Events could be ignored if the inherited value
		 * is to low.
		 * e.g BSF  -> https://issues.apache.org/jira/browse/BSF-24
		 */
		HELLO_LOG.setLevel(Level.ALL);

		/* Start with the default Log4j configuration, which logs to console */
		BasicConfigurator.configure();

		/*
		 * Instantiate a LTTng log appender and attach it to the logger, which
		 * will now send the logged events to UST.
		 */
		Appender lttngAppender = new LttngLogAppender();
		HELLO_LOG.addAppender(lttngAppender);

		/*
		 * Here we've set up the appender programmatically, but it could also be
		 * defined at runtime, by reading a configuration file for example:
		 */
		// PropertyConfigurator.configure(fileName);

		/* Trigger some tracing events using the Log4j Logger created before. */
		HELLO_LOG.info("Hello World, the answer is " + 42);
		HELLO_LOG.info("Another info event");
		HELLO_LOG.error("An error event");

		/* Cleanup */
		HELLO_LOG.removeAppender(lttngAppender);
		lttngAppender.close();
	}
}
