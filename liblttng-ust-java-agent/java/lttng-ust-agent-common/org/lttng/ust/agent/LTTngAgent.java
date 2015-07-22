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

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;

/**
 * The central agent managing the JUL and Log4j handlers.
 *
 * @author David Goulet
 */
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

	private static final int SEM_TIMEOUT = 3; /* Seconds */

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

	/*
	 * Constructor is private. This is a singleton and a reference should be
	 * acquired using getLTTngAgent().
	 */
	private LTTngAgent() {
		initAgentJULClasses();

		/* Since Log4j is a 3rd party JAR, we need to check if we can load any of its classes */
		Boolean log4jLoaded = loadLog4jClasses();
		if (log4jLoaded) {
			initAgentLog4jClasses();
		}

		registerSem = new Semaphore(0, true);
	}

	private static Boolean loadLog4jClasses() {
		Class<?> logging;

		try {
			logging = loadClass("org.apache.log4j.spi.LoggingEvent");
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
			System.err.println("Warning: The loaded log4j library is too old. Log4j tracing with LTTng will be disabled.");
			return false;
		} catch (NullPointerException e) {
			/* Should never happen */
			return false;
		} catch (SecurityException e) {
			return false;
		}

		return true;
	}

	private static Class<?> loadClass(String className) throws ClassNotFoundException {
		ClassLoader loader;
		Class<?> loadedClass;

		try {
			/* Try to load class using the current thread's context class loader */
			loader = Thread.currentThread().getContextClassLoader();
			loadedClass = loader.loadClass(className);
		} catch (ClassNotFoundException e) {
			/* Loading failed, try using the system class loader */
			loader = ClassLoader.getSystemClassLoader();
			loadedClass = loader.loadClass(className);
		}

		return loadedClass;
	}

	private void initAgentJULClasses() {
		try {
			Class<?> lttngJUL = loadClass("org.lttng.ust.agent.jul.LTTngJUL");
			julUser = (LogFramework) lttngJUL.getDeclaredConstructor(new Class[] { Boolean.class }).newInstance(false);
			julRoot = (LogFramework) lttngJUL.getDeclaredConstructor(new Class[] { Boolean.class }).newInstance(true);
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
			Class<?> lttngLog4j = loadClass("org.lttng.ust.agent.log4j.LTTngLog4j");
			log4jUser = (LogFramework)lttngLog4j.getDeclaredConstructor(new Class[] {Boolean.class}).newInstance(false);
			log4jRoot = (LogFramework)lttngLog4j.getDeclaredConstructor(new Class[] {Boolean.class}).newInstance(true);
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

	/**
	 * Public getter to acquire a reference to this singleton object.
	 *
	 * @return The agent instance
	 * @throws IOException
	 */
	public static synchronized LTTngAgent getLTTngAgent() throws IOException {
		if (curAgent == null) {
			curAgent = new LTTngAgent();
			curAgent.init();
		}

		return curAgent;
	}

	private synchronized void init() throws SecurityException {
		if (initialized) {
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
			registerSem.tryAcquire(numThreads,
						    SEM_TIMEOUT,
						    TimeUnit.SECONDS);
		} catch (InterruptedException e) {
			e.printStackTrace();
		}

		initialized = true;
	}

	private synchronized static Integer initJULClientThreads() {
		Integer numThreads = 2;

		/* Handle user session daemon if any. */
		julUserClient = new LTTngTCPSessiondClient(Domain.JUL,
								julUser,
								registerSem);

		String userThreadName = "LTTng UST agent JUL user thread";
		sessiondThreadJULUser = new Thread(julUserClient, userThreadName);
		sessiondThreadJULUser.setDaemon(true);
		sessiondThreadJULUser.start();

		/* Handle root session daemon. */
		julRootClient = new LTTngTCPSessiondClient(Domain.JUL,
								julRoot,
								registerSem);

		String rootThreadName = "LTTng UST agent JUL root thread";
		sessiondThreadJULRoot = new Thread(julRootClient, rootThreadName);
		sessiondThreadJULRoot.setDaemon(true);
		sessiondThreadJULRoot.start();

		return numThreads;
	}

	private synchronized static Integer initLog4jClientThreads() {
		Integer numThreads = 2;

		log4jUserClient = new LTTngTCPSessiondClient(Domain.LOG4J,
								  log4jUser,
								  registerSem);

		String userThreadName = "LTTng UST agent Log4j user thread";
		sessiondThreadLog4jUser = new Thread(log4jUserClient, userThreadName);
		sessiondThreadLog4jUser.setDaemon(true);
		sessiondThreadLog4jUser.start();

		log4jRootClient = new LTTngTCPSessiondClient(Domain.LOG4J,
								  log4jRoot,
								  registerSem);

		String rootThreadName = "LTTng UST agent Log4j root thread";
		sessiondThreadLog4jRoot = new Thread(log4jRootClient,rootThreadName);
		sessiondThreadLog4jRoot.setDaemon(true);
		sessiondThreadLog4jRoot.start();

		return numThreads;
	}

	/**
	 * Dispose the agent. Applications should call this once they are done
	 * logging.
	 */
	public void dispose() {
		if (this.useJUL) {
			julUserClient.destroy();
			julRootClient.destroy();
			julUser.reset();
			julRoot.reset();
		}

		if (this.useLog4j) {
			log4jUserClient.destroy();
			log4jRootClient.destroy();
			log4jUser.reset();
			log4jRoot.reset();
		}

		try {
			if (this.useJUL) {
				sessiondThreadJULUser.join();
				sessiondThreadJULRoot.join();
			}

			if (this.useLog4j) {
				sessiondThreadLog4jUser.join();
				sessiondThreadLog4jRoot.join();
			}

		} catch (InterruptedException e) {
			e.printStackTrace();
		}
	}
}
