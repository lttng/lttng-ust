/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2022 EfficiOS Inc.
 */

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.core.config.Configurator;
import org.apache.logging.log4j.core.config.builder.api.AppenderComponentBuilder;
import org.apache.logging.log4j.core.config.builder.api.ConfigurationBuilder;
import org.apache.logging.log4j.core.config.builder.api.ConfigurationBuilderFactory;
import org.apache.logging.log4j.core.config.builder.api.LayoutComponentBuilder;
import org.apache.logging.log4j.core.config.builder.api.RootLoggerComponentBuilder;
import org.apache.logging.log4j.core.config.builder.impl.BuiltConfiguration;

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
public class HelloLog4j2Prog {

	/**
	 * Application start
	 *
	 * @param args Command-line arguments
	 */
	public static void main(String args[]) {

		ConfigurationBuilder<BuiltConfiguration> builder = ConfigurationBuilderFactory.newConfigurationBuilder();

		/* Layout */
		LayoutComponentBuilder standardLayout = builder.newLayout("PatternLayout");
		standardLayout.addAttribute("pattern", "%d [%t] %-5level: %msg%n%throwable");

		/* Create a console appender */
		AppenderComponentBuilder appenderBuilder = builder.newAppender("Stdout", "CONSOLE");
		appenderBuilder.add(standardLayout);
		builder.add(appenderBuilder);

		/* Create an Lttng appender */
		appenderBuilder = builder.newAppender("Lttng", "LTTNG");
		builder.add(appenderBuilder);

		/* Create a root logger with both appenders attached */
		RootLoggerComponentBuilder rootLogger = builder.newRootLogger(Level.DEBUG);
		rootLogger.add(builder.newAppenderRef("Stdout"));
		rootLogger.add(builder.newAppenderRef("Lttng"));
		builder.add(rootLogger);

		Configurator.initialize(builder.build());

		Logger logger = LogManager.getLogger(HelloLog4j2Prog.class);

		/* Trigger some tracing events using the Log4j Logger created before. */
		logger.info("Prog config: Hello World, the answer is " + 42);
		logger.info("Prog config: Another info event");
		logger.error("Prog config: An error event");
	}
}
