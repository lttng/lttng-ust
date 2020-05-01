/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2016 EfficiOS Inc.
 * Copyright (C) 2016 Alexandre Montplaisir <alexmonthy@efficios.com>
 */

import java.io.IOException;
import java.util.logging.Handler;
import java.util.logging.Logger;

import org.lttng.ust.agent.context.ContextInfoManager;
import org.lttng.ust.agent.context.IContextInfoRetriever;
import org.lttng.ust.agent.jul.LttngLogHandler;

/**
 * Example program defining a application context retriever, which allows
 * attaching application-defined contexts to trace events.
 *
 * FIXME Use custom context names, and several names/types
 *
 * <p>
 * Usage:
 * <ul>
 * <li>$ lttng create</li>
 * <li>$ lttng enable-event -j -a</li>
 * <li>$ lttng add-context -j -t '$app.myprovider:mystringcontext'</li>
 * <li>$ lttng add-context -j -t '$app.myprovider:myshortcontext'</li>
 * <li>$ lttng start</li>
 * <li>(run this program)</li>
 * <li>$ lttng stop</li>
 * <li>$ lttng view</li>
 * <li>$ lttng destroy</li>
 * </ul>
 * </p>
 *
 * The events present in the resulting trace should carry the context
 * information defined in the example retriever.
 *
 * @author Alexandre Montplaisir
 */
public class ApplicationContextExample {

	/** Class-wide JUL logger object */
	private static final Logger LOGGER = Logger.getLogger(ApplicationContextExample.class.getName());

	private static final String RETRIEVER_NAME = "myprovider";
	private static final String CONTEXT_NAME_STRING = "mystringcontext";
	private static final String CONTEXT_NAME_SHORT = "myshortcontext";

	private static class ExampleContextInfoRetriever implements IContextInfoRetriever {

		@Override
		public Object retrieveContextInfo(String key) {
			if (CONTEXT_NAME_SHORT.equals(key)) {
				return (short) 42;
			} else if (CONTEXT_NAME_STRING.equals(key)) {
				return "context-value!";
			} else {
				return null;
			}
		}

	}

	/**
	 * Application start
	 *
	 * @param args
	 *            Command-line arguments
	 * @throws IOException
	 * @throws InterruptedException
	 */
	public static void main(String args[]) throws IOException, InterruptedException {
		/* Instantiate and attach a logger object */
		Handler lttngHandler = new LttngLogHandler();
		LOGGER.addHandler(lttngHandler);

		/* Instantiate and register the context retriever */
		IContextInfoRetriever cir = new ExampleContextInfoRetriever();
		ContextInfoManager.getInstance().registerContextInfoRetriever(RETRIEVER_NAME, cir);

		/*
		 * Make sure you have a LTTng session running with the appropriate
		 * events and contexts enabled! See the class Javadoc.
		 */

		/* Trigger a tracing event using the JUL Logger created before. */
		LOGGER.info("Log event #1");
		LOGGER.warning("Log event #2");
		LOGGER.severe("Log event #3");

		/* Unregister our context retriever, and dispose the log handler */
		ContextInfoManager.getInstance().unregisterContextInfoRetriever(RETRIEVER_NAME);
		lttngHandler.close();
	}
}
