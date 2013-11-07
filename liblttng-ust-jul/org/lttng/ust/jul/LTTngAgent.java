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

package org.lttng.ust.jul;

import java.io.IOException;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.io.BufferedReader;
import java.io.FileReader;
import java.util.concurrent.Semaphore;
import java.util.logging.FileHandler;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.logging.LogManager;
import java.util.Enumeration;

public class LTTngAgent {
	private static LTTngLogHandler lttngHandler;
	private static LogManager logManager;
	private static LTTngThread lttngThread;
	private static Thread sessiondTh;

	/* Singleton agent object. */
	private static LTTngAgent curAgent = null;

	/* Indicate if this object has been initialized. */
	private static boolean initialized = false;

	private static Semaphore registerSem;

	private static final String sessiondAddr = "127.0.0.1";
	private static final int sessiondPort = 5345;

	private static final String rootPortFile = "/var/run/lttng/jul.port";
	private static final String userPortFile = "/.lttng/jul.port";

	/*
	 * Constructor is private. This is a singleton and a reference should be
	 * acquired using getLTTngAgent().
	 */
	private LTTngAgent() throws IOException {
		this.logManager = LogManager.getLogManager();
		this.lttngHandler = new LTTngLogHandler(this.logManager);
		this.registerSem = new Semaphore(0, true);
	}

	private void removeHandlers() throws SecurityException, IOException {
		String loggerName;
		Logger logger;

		Enumeration list = this.logManager.getLoggerNames();
		while (list.hasMoreElements()) {
			loggerName = list.nextElement().toString();
			/* Somehow there is always an empty string at the end. */
			if (loggerName == "") {
				continue;
			}

			logger = this.logManager.getLogger(loggerName);
			logger.removeHandler(this.lttngHandler);
		}
	}

	private int getUID() throws IOException {
		int uid;
		byte b[] = new byte[4];
		String userName = System.getProperty("user.name");
		String command = "id -u " + userName;
		Process child = Runtime.getRuntime().exec(command);
		InputStream in = child.getInputStream();

		in.read(b);
		uid = Integer.parseInt(new String(b).trim(), 10);
		in.close();

		return uid;
	}

	private String getHomePath() {
		return System.getProperty("user.home");
	}

	private int getPortFromFile() throws IOException {
		int port;
		int uid = getUID();
		String path;
		BufferedReader br;

		/* Check if root or not, it tells where to get the port file. */
		if (uid == 0) {
			path = rootPortFile;
		} else {
			path = new String(getHomePath() + userPortFile);
		}

		try {
			br = new BufferedReader(new FileReader(path));
			String line = br.readLine();
			port = Integer.parseInt(line, 10);
			if (port < 0 || port > 65535) {
				port = sessiondPort;
			}
			br.close();
		} catch (FileNotFoundException e) {
			port = sessiondPort;
		}

		return port;
	}

	/*
	 * Public getter to acquire a reference to this singleton object.
	 */
	public static synchronized LTTngAgent getLTTngAgent() throws IOException {
		if (curAgent == null) {
			curAgent = new LTTngAgent();
			curAgent.init();
		}

		return curAgent;
	}

	/*
	 * Initialize LTTngAgent. This will attach the log handler to all Logger
	 * returned by the logManager.
	 */
	private synchronized void init() throws SecurityException, IOException {
		if (this.initialized) {
			return;
		}

		this.lttngThread = new LTTngThread(this.sessiondAddr,
				getPortFromFile(), this.lttngHandler, this.registerSem);
		this.sessiondTh = new Thread(lttngThread);
		this.sessiondTh.start();

		this.initialized = true;

		/* Wait for the registration to end. */
		try {
			this.registerSem.acquire();
		} catch (InterruptedException e) {
			e.printStackTrace();
		}
	}

	public void dispose() throws IOException {
		this.lttngThread.dispose();

		/* Make sure there is no more LTTng handler attach to logger(s). */
		this.removeHandlers();

		try {
			this.sessiondTh.join();
		} catch (InterruptedException e) {
			e.printStackTrace();
		}
	}
}
