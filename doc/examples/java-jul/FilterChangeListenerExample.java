/*
 * Copyright (C) 2015 - EfficiOS Inc., Alexandre Montplaisir <alexmonthy@efficios.com>
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

import org.lttng.ust.agent.ILttngHandler;
import org.lttng.ust.agent.filter.FilterChangeNotifier;
import org.lttng.ust.agent.filter.IFilterChangeListener;
import org.lttng.ust.agent.jul.LttngLogHandler;
import org.lttng.ust.agent.session.EventRule;
import org.lttng.ust.agent.session.LogLevelSelector;

/**
 * Example usage of a {@link IFilterChangeListener}.
 *
 * This listener will simply print to stdout the notifications it receives. To
 * try it, run the program, then issue "lttng enable-event" and
 * "lttng disable-event" commands for the JUL domain.
 *
 * @author Alexandre Montplaisir
 */
public class FilterChangeListenerExample {

	private static class ExampleFilterChangeListener implements IFilterChangeListener {

		@Override
		public void eventRuleAdded(EventRule rule) {
			System.out.println();
			System.out.println("New event rule enabled:");
			System.out.println("Event name: " + rule.getEventName());
			System.out.println(printLogLevel(rule.getLogLevelSelector()));
			System.out.println("Filter string: " + rule.getFilterString());
		}

		@Override
		public void eventRuleRemoved(EventRule rule) {
			System.out.println();
			System.out.println("Event rule disabled:");
			System.out.println("Event name: " + rule.getEventName());
			System.out.println(printLogLevel(rule.getLogLevelSelector()));
			System.out.println("Filter string: " + rule.getFilterString());
		}

		/**
		 * Convenience method to print integer log level values into their JUL
		 * equivalent.
		 */
		private static String printLogLevel(LogLevelSelector lls) {
			String llname = Level.parse(String.valueOf(lls.getLogLevel())).getName();
			return "Log level: " + llname + ", filter type: " + lls.getLogLevelType().toString();
		}
	}

	/**
	 * Run the program.
	 *
	 * @param args
	 *            Command-line arguments (not used)
	 * @throws IOException
	 */
	public static void main(String args[]) throws IOException {
		/* We need at least one log handler to activate the LTTng agent */
		ILttngHandler handler = new LttngLogHandler();

		/* Create a listener and register it to the manager */
		IFilterChangeListener listener = new ExampleFilterChangeListener();
		FilterChangeNotifier.getInstance().registerListener(listener);

		System.out.println("Press Enter to finish.");
		System.in.read();

		/* Unregister the listener */
		FilterChangeNotifier.getInstance().unregisterListener(listener);

		/* Cleanup the log handler we created */
		handler.close();
	}
}
