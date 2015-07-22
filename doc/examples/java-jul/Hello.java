/*
 * Copyright (C) 2015 - EfficiOS Inc., Alexandre Montplaisir <alexmonthy@efficios.com>
 * Copyright (C) 2013 - David Goulet <dgoulet@efficios.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
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
	 * @throws InterruptedException
	 */
	public static void main(String args[]) throws IOException, InterruptedException {

		/* Instantiate a LTTngLogHandler object, and attach it to our logger */
		Handler lttngHandler = new LttngLogHandler();
		LOGGER.addHandler(lttngHandler);

		/*
		 * Gives you time to do some lttng commands before any event is hit.
		 */
		Thread.sleep(5000);

		/* Trigger a tracing event using the JUL Logger created before. */
		LOGGER.info("Hello World, the answer is " + 42);

		/*
		 * From this point on, the above message will be collected in the trace
		 * if the event "Hello" is enabled for the JUL domain using the lttng
		 * command line or the lttng-ctl API. For instance:
		 *
		 *   $ lttng enable-event -j Hello
		 */

		/*
		 * A new logger is created here and fired after. Typically with JUL, you
		 * use one static Logger per class. This example here can represent a
		 * class being lazy-loaded later in the execution of the application.
		 *
		 * The agent has an internal timer that is fired every 5 seconds in
		 * order to enable events that were not found at first but might need to
		 * be enabled when a new Logger appears. Unfortunately, there is no way
		 * right now to get notified of that so we have to actively poll.
		 *
		 * Using the --all command for instance, it will make this Logger
		 * available in a LTTng trace after the internal agent's timer is fired.
		 * (lttng enable-event -j -a).
		 */
		Logger helloLogDelayed = Logger.getLogger("hello_delay");

		/*
		 * Attach a handler to this new logger.
		 *
		 * Using the same handler as before would also work.
		 */
		Handler lttngHandler2 = new LttngLogHandler();
		helloLogDelayed.addHandler(lttngHandler2);

		System.out.println("Firing hello delay in 10 seconds...");
		Thread.sleep(10000);
		helloLogDelayed.info("Hello World delayed...");

		System.out.println("Cleaning Hello");

		/*
		 * Do not forget to close() all handlers so that the agent can shutdown
		 * and the session daemon socket gets cleaned up explicitly.
		 */
		lttngHandler.close();
		lttngHandler2.close();
	}
}
