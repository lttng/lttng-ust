/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2022 EfficiOS Inc.
 */

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

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
public class HelloLog4j2 {

	private static final Logger logger = LogManager.getLogger(HelloLog4j2.class);

	/**
	 * Application start
	 *
	 * @param args Command-line arguments
	 */
	public static void main(String args[]) {

		/* Trigger some tracing events using the Log4j Logger created before. */
		logger.info("Basic config: Hello World, the answer is " + 42);
		logger.info("Basic config: Another info event");
		logger.error("Basic config: An error event");
	}
}
