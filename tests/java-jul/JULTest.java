/*
 * Copyright (C) 2013 - David Goulet <dgoulet@efficios.com>
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License, version 2.1 only,
 * as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
 * for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

import java.io.IOException;
import java.util.concurrent.Semaphore;
import java.util.logging.LogManager;

import org.lttng.ust.jul.*;

public class JULTest {
	private final static int NUM_TESTS = 5;
	private static int testCount = 1;

	/* Singleton agent object. */
	private static LTTngAgent agent;
	private static LTTngLogHandler handler;
	private static LTTngTCPSessiondClient client;

	private static Semaphore sem;

	private static void ok(String desc) {
		System.out.println("ok " + testCount + " - " + desc);
		testCount++;
	}

	public static void go() throws IOException {
		handler = new LTTngLogHandler(LogManager.getLogManager());
		assert handler.logManager == LogManager.getLogManager();
		ok("Log handler logManager is valid");

		client = new LTTngTCPSessiondClient("127.0.0.1", 5345, sem);
		assert client != null;
		ok("TCP client is valid");
		client.destroy();
		ok("TCP client destroyed");

		agent = LTTngAgent.getLTTngAgent();
		assert agent != null;
		ok("LTTngAgent is valid");
		agent.dispose();
		ok("LTTngAgent disposed");
	}

	public static void main(String args[]) throws Exception {
		System.out.println("1.." + NUM_TESTS);
		go();
	}
}
