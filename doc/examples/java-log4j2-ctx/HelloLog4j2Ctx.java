/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2022 EfficiOS Inc.
 */

import java.net.URI;
import java.util.ArrayList;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.core.LoggerContext;

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
 */
public class HelloLog4j2Ctx {

	/**
	 * Application start
	 *
	 * @param args Command-line arguments
	 */
	public static void main(String args[]) {

		URI configFileUri1 = URI.create("./log4j2.ctx1.xml");
		URI configFileUri2 = URI.create("./log4j2.ctx2.xml");

		LoggerContext loggerContext1 = (LoggerContext) LogManager.getContext(ClassLoader.getSystemClassLoader(), false,
				configFileUri1);
		LoggerContext loggerContext2 = (LoggerContext) LogManager.getContext(ClassLoader.getSystemClassLoader(), false,
				configFileUri2);

		/* Loggers in different contexts with the same name. */
		Logger logger1ctx1 = loggerContext1.getLogger(HelloLog4j2Ctx.class);
		Logger logger1ctx2 = loggerContext2.getLogger(HelloLog4j2Ctx.class);

		Logger logger2ctx1 = loggerContext1.getLogger("Logger2");
		Logger logger3ctx2 = loggerContext2.getLogger("Logger3");

		ArrayList<Logger> loggers = new ArrayList<Logger>();

		loggers.add(logger1ctx1);
		loggers.add(logger1ctx2);
		loggers.add(logger2ctx1);
		loggers.add(logger3ctx2);

		for (Logger logger : loggers) {
			/* Trigger some tracing events using the Log4j Logger created before. */
			logger.info("Context config: Hello World, the answer is " + 42);
			logger.info("Context config: Another info event");
			logger.error("Context config: An error event");
		}
	}
}
