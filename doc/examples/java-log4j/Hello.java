/*
 * Copyright (C) 2015 - EfficiOS Inc., Alexandre Montplaisir <alexmonthy@efficios.com>
 * Copyright (C) 2014 - Christian Babeux <christian.babeux@efficios.com>
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

import org.apache.log4j.Appender;
import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.Logger;
import org.lttng.ust.agent.log4j.LttngLogAppender;

/**
 * Example application using the LTTng-UST Java JUL agent.
 *
 * @author Alexandre Montplaisir
 * @author Christian Babeux
 */
public class Hello {

	private static final Logger HELLO_LOG = Logger.getLogger(Hello.class);

	/**
	 * Application start
	 *
	 * @param args
	 *            Command-line arguments
	 * @throws IOException
	 * @throws InterruptedException
	 */
	public static void main(String args[]) throws IOException, InterruptedException {
		/* Start with the default Log4j configuration, which logs to console */
		BasicConfigurator.configure();

		/*
		 * Add a LTTng log appender to the logger, which will also send the
		 * logged events to UST.
		 */
		Appender lttngAppender = new LttngLogAppender();
		HELLO_LOG.addAppender(lttngAppender);

		/*
		 * Here we've set up the appender programmatically, but it could also be
		 * defined at runtime, by reading a configuration file for example:
		 */
		// PropertyConfigurator.configure(fileName);

		/*
		 * Gives you time to do some lttng commands before any event is hit.
		 */
		Thread.sleep(5000);

		/* Trigger a tracing event using the Log4j Logger created before. */
		HELLO_LOG.info("Hello World, the answer is " + 42);

		System.out.println("Firing second event in 5 seconds...");
		Thread.sleep(5000);
		HELLO_LOG.info("Hello World delayed...");

		lttngAppender.close();
	}
}
