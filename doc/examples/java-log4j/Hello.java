/*
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

import org.apache.log4j.Logger;
import org.apache.log4j.BasicConfigurator;

import org.lttng.ust.agent.LTTngAgent;

public class Hello
{
	/* Of course :) */
	private static final int answer = 42;

	static Logger helloLog = Logger.getLogger(Hello.class);

	private static LTTngAgent lttngAgent;

	public static void main(String args[]) throws Exception
	{
		BasicConfigurator.configure();
		lttngAgent = LTTngAgent.getLTTngAgent();

		/*
		 * Gives you time to do some lttng commands before any event is hit.
		 */
		Thread.sleep(5000);

		/* Trigger a tracing event using the JUL Logger created before. */
		helloLog.info("Hello World, the answer is " + answer);

		System.out.println("Firing hello delay in 5 seconds...");
		Thread.sleep(5000);
		helloLog.info("Hello World delayed...");
	}
}
