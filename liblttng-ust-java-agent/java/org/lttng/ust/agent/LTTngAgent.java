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

package org.lttng.ust.agent;

import org.lttng.ust.agent.jul.LTTngJUL;

import java.io.IOException;
import java.io.InputStream;
import java.io.BufferedReader;
import java.io.FileReader;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.Enumeration;
import java.lang.reflect.InvocationTargetException;

import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;

public class LTTngAgent {
	/* Domains */
	static enum Domain {
		JUL(3), LOG4J(4);
		private int value;

		private Domain(int value) {
			this.value = value;
		}

		public int value() {
			return value;
		}
	}

	private static LogFramework julUser;
	private static LogFramework julRoot;
	private static LogFramework log4jUser;
	private static LogFramework log4jRoot;

	/* Sessiond clients */
	private static LTTngTCPSessiondClient julUserClient;
	private static LTTngTCPSessiondClient julRootClient;
	private static LTTngTCPSessiondClient log4jUserClient;
	private static LTTngTCPSessiondClient log4jRootClient;

	private static Thread sessiondThreadJULUser;
	private static Thread sessiondThreadJULRoot;
	private static Thread sessiondThreadLog4jUser;
	private static Thread sessiondThreadLog4jRoot;

	private boolean useJUL = false;
	private boolean useLog4j = false;

	/* Singleton agent object */
	private static LTTngAgent curAgent = null;

	/* Indicate if this object has been initialized. */
	private static boolean initialized = false;

	private static Semaphore registerSem;
	private final static int semTimeout = 3; /* Seconds */

	/*
	 * Constructor is private. This is a singleton and a reference should be
	 * acquired using getLTTngAgent().
	 */
	private LTTngAgent() throws IOException {
		initAgentJULClasses();

		/* Since Log4j is a 3rd party JAR, we need to check if we can load any of its classes */
		Boolean log4jLoaded = loadLog4jClasses();
		if (log4jLoaded) {
			initAgentLog4jClasses();
		}

		this.registerSem = new Semaphore(0, true);
	}

	private Boolean loadLog4jClasses() {
		Class<?> logging;

		try {
			ClassLoader loader = ClassLoader.getSystemClassLoader();
			logging = loader.loadClass("org.apache.log4j.spi.LoggingEvent");
		} catch (ClassNotFoundException e) {
			/* Log4j classes not found, no need to create the relevant objects */
			return false;
		}

		/*
		 * Detect capabilities of the log4j library. We only
		 * support log4j >= 1.2.15.  The getTimeStamp() method
		 * was introduced in log4j 1.2.15, so verify that it
		 * is available.
		 *
		 * We can't rely on the getPackage().getImplementationVersion()
		 * call that would retrieves information from the manifest file
		 * found in the JAR since the manifest file shipped
		 * from upstream is known to be broken in several
		 * versions of the library.
		 *
		 * More info:
		 * https://issues.apache.org/bugzilla/show_bug.cgi?id=44370
		 */

		try {
			logging.getDeclaredMethod("getTimeStamp");
		} catch (NoSuchMethodException e) {
			return false;
		} catch (NullPointerException e) {
			/* Should never happen */
			return false;
		} catch (SecurityException e) {
			return false;
		}

		return true;
	}

	private void initAgentJULClasses() {
		try {
			ClassLoader loader = ClassLoader.getSystemClassLoader();
			Class<?> lttngJUL = loader.loadClass("org.lttng.ust.agent.jul.LTTngJUL");
			this.julUser = (LogFramework)lttngJUL.getDeclaredConstructor(new Class[] {Boolean.class}).newInstance(false);
			this.julRoot = (LogFramework)lttngJUL.getDeclaredConstructor(new Class[] {Boolean.class}).newInstance(true);
			this.useJUL = true;
		} catch (ClassNotFoundException e) {
			/* LTTng JUL classes not found, no need to create the relevant objects */
			this.useJUL = false;
		} catch (InstantiationException e) {
			this.useJUL = false;
		} catch (NoSuchMethodException e) {
			this.useJUL = false;
		} catch (IllegalAccessException e) {
			this.useJUL = false;
		} catch (InvocationTargetException e) {
			this.useJUL = false;
		}
	}

	private void initAgentLog4jClasses() {
		try {
			ClassLoader loader = ClassLoader.getSystemClassLoader();
			Class<?> lttngLog4j = loader.loadClass("org.lttng.ust.agent.log4j.LTTngLog4j");
			this.log4jUser = (LogFramework)lttngLog4j.getDeclaredConstructor(new Class[] {Boolean.class}).newInstance(false);
			this.log4jRoot = (LogFramework)lttngLog4j.getDeclaredConstructor(new Class[] {Boolean.class}).newInstance(true);
			this.useLog4j = true;
		} catch (ClassNotFoundException e) {
			/* LTTng Log4j classes not found, no need to create the relevant objects */
			this.useLog4j = false;
		} catch (InstantiationException e) {
			this.useLog4j = false;
		} catch (NoSuchMethodException e) {
			this.useLog4j = false;
		} catch (IllegalAccessException e) {
			this.useLog4j = false;
		} catch (InvocationTargetException e) {
			this.useLog4j = false;
		}
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

	private synchronized void init() throws SecurityException, IOException {
		if (this.initialized) {
			return;
		}

		Integer numJULThreads = 0;
		Integer numLog4jThreads = 0;

		if (this.useJUL) {
			numJULThreads = initJULClientThreads();
		}

		if (this.useLog4j) {
			numLog4jThreads = initLog4jClientThreads();
		}

		Integer numThreads = numJULThreads + numLog4jThreads;

		/* Wait for each registration to end. */
		try {
			this.registerSem.tryAcquire(numThreads,
						    semTimeout,
						    TimeUnit.SECONDS);
		} catch (InterruptedException e) {
			e.printStackTrace();
		}

		this.initialized = true;
	}

	private synchronized Integer initJULClientThreads() {
		Integer numThreads = 2;

		/* Handle user session daemon if any. */
		this.julUserClient = new LTTngTCPSessiondClient(Domain.JUL,
								this.julUser,
								this.registerSem);

		String userThreadName = "LTTng UST agent JUL user thread";
		this.sessiondThreadJULUser = new Thread(julUserClient, userThreadName);
		this.sessiondThreadJULUser.setDaemon(true);
		this.sessiondThreadJULUser.start();

		/* Handle root session daemon. */
		this.julRootClient = new LTTngTCPSessiondClient(Domain.JUL,
								this.julRoot,
								this.registerSem);

		String rootThreadName = "LTTng UST agent JUL root thread";
		this.sessiondThreadJULRoot = new Thread(julRootClient, rootThreadName);
		this.sessiondThreadJULRoot.setDaemon(true);
		this.sessiondThreadJULRoot.start();

		return numThreads;
	}

	private synchronized Integer initLog4jClientThreads() {
		Integer numThreads = 2;

		this.log4jUserClient = new LTTngTCPSessiondClient(Domain.LOG4J,
								  this.log4jUser,
								  this.registerSem);

		String userThreadName = "LTTng UST agent Log4j user thread";
		this.sessiondThreadLog4jUser = new Thread(log4jUserClient, userThreadName);
		this.sessiondThreadLog4jUser.setDaemon(true);
		this.sessiondThreadLog4jUser.start();

		this.log4jRootClient = new LTTngTCPSessiondClient(Domain.LOG4J,
								  this.log4jRoot,
								  this.registerSem);

		String rootThreadName = "LTTng UST agent Log4j root thread";
		this.sessiondThreadLog4jRoot = new Thread(log4jRootClient,rootThreadName);
		this.sessiondThreadLog4jRoot.setDaemon(true);
		this.sessiondThreadLog4jRoot.start();

		return numThreads;
	}


	public void dispose() throws IOException {
		if (this.useJUL) {
			this.julUserClient.destroy();
			this.julRootClient.destroy();
			this.julUser.reset();
			this.julRoot.reset();
		}

		if (this.useLog4j) {
			this.log4jUserClient.destroy();
			this.log4jRootClient.destroy();
			this.log4jUser.reset();
			this.log4jRoot.reset();
		}

		try {
			if (this.useJUL) {
				this.sessiondThreadJULUser.join();
				this.sessiondThreadJULRoot.join();
			}

			if (this.useLog4j) {
				this.sessiondThreadLog4jUser.join();
				this.sessiondThreadLog4jRoot.join();
			}

		} catch (InterruptedException e) {
			e.printStackTrace();
		}
	}
}
