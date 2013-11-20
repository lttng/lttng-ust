/*
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
import java.util.logging.Level;
import java.util.logging.Logger;

/*
 * That's the import you need being the path in the liblttng-ust-jul Jar file.
 */
import org.lttng.ust.jul.LTTngAgent;

public class Hello
{
	/* Of course :) */
	private static final int answer = 42;

	/*
	 * Static reference to the LTTngAgent. Used to dispose of it at the end
	 * which is recommended but not mandatory to do.
	 */
	private static LTTngAgent lttngAgent;

	public static void main(String args[]) throws Exception
	{
		/*
		 * For this example, a custom "hello" logger is created. Note that JUL
		 * has a default "global" that can also be used.
		 */
		Logger helloLog = Logger.getLogger("hello");

		/*
		 * Get the LTTngAgent singelton reference. This will also initialize
		 * the Agent and make it register to the session daemon if available.
		 * When this returns, the Agent is registered and fully ready. If no
		 * session daemon is found, it will return and retry every 3 seconds in
		 * the background. TCP is used for communication.
		 *
		 * Note that the LTTngAgent once registered is a seperate thread in
		 * your Java application.
		 */
		lttngAgent = LTTngAgent.getLTTngAgent();

		/*
		 * Gives you time to do some lttng commands before any event is hit.
		 */
		Thread.sleep(5000);

		/* Trigger a tracing event using the JUL Logger created before. */
		helloLog.info("Hello World, the answer is " + answer);

		/*
		 * From this point on, the above message will be collected in the trace
		 * if the event "hello" is enabled for the JUL domain using the lttng
		 * command line or the lttng-ctl API. For instance:
		 *
		 *   $ lttng enable-event -j hello
		 *
		 * A new logger is created here and fired after. The Agent has an
		 * internal timer that is fired every 5 seconds in order to enable
		 * events that were not found at first but might need to be enabled
		 * when new Logger appears. Unfortunately, there is no way right now to
		 * get notify of that so we have to actively poll.
		 *
		 * Using the --all command for instance, it will make this Logger
		 * available in a LTTng trace after the internal Agent's timer is
		 * fired. (lttng enable-event -a -j).
		 */
		Logger helloLogDelayed = Logger.getLogger("hello_delay");

		System.out.println("Firing hello delay in 10 seconds...");
		Thread.sleep(10000);
		helloLogDelayed.info("Hello World delayed...");

		System.out.println("Cleaning Hello");

		/*
		 * Again, this is highly recommended so the session daemon socket gets
		 * cleaned up explicitely but it is not mandatory to do this step.
		 */
		lttngAgent.dispose();
	}
}
