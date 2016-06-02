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

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.logging.Handler;
import java.util.logging.Logger;

/**
 * The central agent managing the JUL and Log4j handlers.
 *
 * @author David Goulet
 * @deprecated Applications are now expected to manage their Logger and Handler
 *             objects.
 */
@Deprecated
public class LTTngAgent {

	private static LTTngAgent instance = null;

	/**
	 * Public getter to acquire a reference to this singleton object.
	 *
	 * @return The agent instance
	 */
	public static synchronized LTTngAgent getLTTngAgent() {
		if (instance == null) {
			instance = new LTTngAgent();
		}
		return instance;
	}

	/**
	 * Dispose the agent. Applications should call this once they are done
	 * logging. This dispose function is non-static for backwards
	 * compatibility purposes.
	 */
	@SuppressWarnings("static-method")
	public void dispose() {
		synchronized (LTTngAgent.class) {
			if (instance != null) {
				instance.disposeInstance();
				instance = null;
			}
		}
		return;
	}

	private ILttngHandler julHandler = null;
	private ILttngHandler log4jAppender = null;

	/**
	 * Private constructor. This is a singleton and a reference should be
	 * acquired using {@link #getLTTngAgent()}.
	 */
	private LTTngAgent() {
		initJulHandler();
		initLog4jAppender();
	}

	/**
	 * "Destructor" method.
	 */
	private void disposeInstance() {
		disposeJulHandler();
		disposeLog4jAppender();
	}

	/**
	 * Create a LTTng-JUL handler, and attach it to the JUL root logger.
	 */
	private void initJulHandler() {
		try {
			Class<?> julHandlerClass = Class.forName("org.lttng.ust.agent.jul.LttngLogHandler");
			/*
			 * It is safer to use Constructor.newInstance() rather than
			 * Class.newInstance(), because it will catch the exceptions thrown
			 * by the constructor below (which happens if the Java library is
			 * present, but the matching JNI one is not).
			 */
			Constructor<?> julHandlerCtor = julHandlerClass.getConstructor();
			julHandler = (ILttngHandler) julHandlerCtor.newInstance();

			/* Attach the handler to the root JUL logger */
			Logger.getLogger("").addHandler((Handler) julHandler);

			/*
			 * If any of the following exceptions happen, it means we could not
			 * find or initialize LTTng JUL classes. We will not setup LTTng JUL
			 * tracing in this case.
			 */
		} catch (SecurityException e) {
		} catch (IllegalAccessException e) {
		} catch (IllegalArgumentException e) {
		} catch (ClassNotFoundException e) {
		} catch (NoSuchMethodException e) {
		} catch (InstantiationException e) {
		} catch (InvocationTargetException e) {
		}
	}

	/**
	 * Create a LTTng-logj4 appender, and attach it to the log4j root logger.
	 */
	private void initLog4jAppender() {
		/*
		 * Since Log4j is a 3rd party library, we first need to check if we can
		 * load any of its classes.
		 */
		if (!testLog4jClasses()) {
			return;
		}

		try {
			Class<?> log4jAppenderClass = Class.forName("org.lttng.ust.agent.log4j.LttngLogAppender");
			Constructor<?> log4jAppendCtor = log4jAppenderClass.getConstructor();
			log4jAppender = (ILttngHandler) log4jAppendCtor.newInstance();

			/*
			 * If any of the following exceptions happen, it means we could not
			 * find or initialize LTTng log4j classes. We will not setup LTTng
			 * log4j tracing in this case.
			 */
		} catch (SecurityException e) {
			return;
		} catch (ClassNotFoundException e) {
			return;
		} catch (NoSuchMethodException e) {
			return;
		} catch (IllegalArgumentException e) {
			return;
		} catch (InstantiationException e) {
			return;
		} catch (IllegalAccessException e) {
			return;
		} catch (InvocationTargetException e) {
			return;
		}

		/*
		 * Attach the appender to the root Log4j logger. Slightly more tricky
		 * here, as log4j.Logger is not in the base Java library, and we do not
		 * want the "common" package to depend on log4j. So we have to obtain it
		 * through reflection too.
		 */
		try {
			Class<?> loggerClass = Class.forName("org.apache.log4j.Logger");
			Class<?> appenderClass = Class.forName("org.apache.log4j.Appender");

			Method getRootLoggerMethod = loggerClass.getMethod("getRootLogger", (Class<?>[]) null);
			Method addAppenderMethod = loggerClass.getMethod("addAppender", appenderClass);

			Object rootLogger = getRootLoggerMethod.invoke(null, (Object[]) null);
			addAppenderMethod.invoke(rootLogger, log4jAppender);

			/*
			 * We have checked for the log4j library version previously, none of
			 * the following exceptions should happen.
			 */
		} catch (SecurityException e) {
			throw new IllegalStateException(e);
		} catch (ClassNotFoundException e) {
			throw new IllegalStateException(e);
		} catch (NoSuchMethodException e) {
			throw new IllegalStateException(e);
		} catch (IllegalArgumentException e) {
			throw new IllegalStateException(e);
		} catch (IllegalAccessException e) {
			throw new IllegalStateException(e);
		} catch (InvocationTargetException e) {
			throw new IllegalStateException(e);
		}
	}

	/**
	 * Check if log4j >= 1.2.15 library is present.
	 */
	private static boolean testLog4jClasses() {
		Class<?> loggingEventClass;

		try {
			loggingEventClass = Class.forName("org.apache.log4j.spi.LoggingEvent");
		} catch (ClassNotFoundException e) {
			/*
			 * Log4j classes not found, no need to create the relevant objects
			 */
			return false;
		}

		/*
		 * Detect capabilities of the log4j library. We only support log4j >=
		 * 1.2.15. The getTimeStamp() method was introduced in log4j 1.2.15, so
		 * verify that it is available.
		 *
		 * We can't rely on the getPackage().getImplementationVersion() call
		 * that would retrieves information from the manifest file found in the
		 * JAR since the manifest file shipped from upstream is known to be
		 * broken in several versions of the library.
		 *
		 * More info: https://issues.apache.org/bugzilla/show_bug.cgi?id=44370
		 */
		try {
			loggingEventClass.getDeclaredMethod("getTimeStamp");
		} catch (NoSuchMethodException e) {
			System.err.println(
					"Warning: The loaded log4j library is too old. Log4j tracing with LTTng will be disabled.");
			return false;
		} catch (SecurityException e) {
			return false;
		}

		return true;
	}

	/**
	 * Detach the JUL handler from its logger and close it.
	 */
	private void disposeJulHandler() {
		if (julHandler == null) {
			/* The JUL handler was not activated, we have nothing to do */
			return;
		}
		Logger.getLogger("").removeHandler((Handler) julHandler);
		julHandler.close();
		julHandler = null;
	}

	/**
	 * Detach the log4j appender from its logger and close it.
	 */
	private void disposeLog4jAppender() {
		if (log4jAppender == null) {
			/* The log4j appender was not active, we have nothing to do */
			return;
		}

		/*
		 * Detach the appender from the log4j root logger. Again, we have to do
		 * this via reflection.
		 */
		try {
			Class<?> loggerClass = Class.forName("org.apache.log4j.Logger");
			Class<?> appenderClass = Class.forName("org.apache.log4j.Appender");

			Method getRootLoggerMethod = loggerClass.getMethod("getRootLogger", (Class<?>[]) null);
			Method removeAppenderMethod = loggerClass.getMethod("removeAppender", appenderClass);

			Object rootLogger = getRootLoggerMethod.invoke(null, (Object[]) null);
			removeAppenderMethod.invoke(rootLogger, log4jAppender);

			/*
			 * We were able to attach the appender previously, we should not
			 * have problems here either!
			 */
		} catch (SecurityException e) {
			throw new IllegalStateException(e);
		} catch (ClassNotFoundException e) {
			throw new IllegalStateException(e);
		} catch (NoSuchMethodException e) {
			throw new IllegalStateException(e);
		} catch (IllegalArgumentException e) {
			throw new IllegalStateException(e);
		} catch (IllegalAccessException e) {
			throw new IllegalStateException(e);
		} catch (InvocationTargetException e) {
			throw new IllegalStateException(e);
		}

		/* Close the appender */
		log4jAppender.close();
		log4jAppender = null;
	}

}
