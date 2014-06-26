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
import java.io.InputStream;
import java.io.BufferedReader;
import java.io.FileReader;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.logging.FileHandler;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.logging.LogManager;
import java.util.Enumeration;

public class LTTngAgent {
	private static LogManager logManager;

	/* Possible that we have to threads handling two sessiond. */
	private static LTTngLogHandler lttngHandlerRoot;
	private static LTTngLogHandler lttngHandlerUser;
	private static LTTngThread lttngThreadRoot;
	private static LTTngThread lttngThreadUser;
	private static Thread sessiondThRoot;
	private static Thread sessiondThUser;

	/* Singleton agent object. */
	private static LTTngAgent curAgent = null;

	/* Indicate if this object has been initialized. */
	private static boolean initialized = false;

	private static Semaphore registerSem;
	private final static int semTimeout = 3; /* Seconds */

	/*
	 * Default value to connect to session daemon. Port number is dynamically
	 * fetched from the port file that is created by a running session daemon.
	 */
	private static final String sessiondAddr = "127.0.0.1";

	/*
	 * Constructor is private. This is a singleton and a reference should be
	 * acquired using getLTTngAgent().
	 */
	private LTTngAgent() throws IOException {
		this.logManager = LogManager.getLogManager();
		this.lttngHandlerUser = new LTTngLogHandler(this.logManager);
		this.lttngHandlerRoot = new LTTngLogHandler(this.logManager);
		this.lttngHandlerRoot.is_root = 1;
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
			logger.removeHandler(this.lttngHandlerUser);
			logger.removeHandler(this.lttngHandlerRoot);
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
		int nr_acquires = 0;

		if (this.initialized) {
			return;
		}

		/* Handle user session daemon if any. */
		this.lttngThreadUser = new LTTngThread(this.sessiondAddr,
				this.lttngHandlerUser, this.registerSem);
		this.sessiondThUser = new Thread(lttngThreadUser);
		this.sessiondThUser.setDaemon(true);
		this.sessiondThUser.start();
		/* Wait for registration done of per-user sessiond */
		nr_acquires++;

		/* Handle root session daemon. */
		this.lttngThreadRoot = new LTTngThread(this.sessiondAddr,
				this.lttngHandlerRoot, this.registerSem);
		this.sessiondThRoot = new Thread(lttngThreadRoot);
		this.sessiondThRoot.setDaemon(true);
		this.sessiondThRoot.start();
		/* Wait for registration done of system-wide sessiond */
		nr_acquires++;

		/* Wait for each registration to end. */
		try {
			this.registerSem.tryAcquire(nr_acquires, semTimeout,
					TimeUnit.SECONDS);
		} catch (InterruptedException e) {
			e.printStackTrace();
		}

		this.initialized = true;
	}

	public void dispose() throws IOException {
		this.lttngThreadUser.dispose();
		if (this.lttngThreadRoot != null) {
			this.lttngThreadRoot.dispose();
		}

		/* Make sure there is no more LTTng handler attach to logger(s). */
		this.removeHandlers();

		try {
			this.sessiondThUser.join();
			if (this.sessiondThRoot != null) {
				this.sessiondThRoot.join();
			}
		} catch (InterruptedException e) {
			e.printStackTrace();
		}
	}
}
