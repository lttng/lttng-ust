/*
 * Copyright (C) 2015 - EfficiOS Inc., Alexandre Montplaisir <alexmonthy@efficios.com>
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

package org.lttng.ust.agent.context;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The singleton manager of {@link IContextInfoRetriever} objects.
 *
 * @author Alexandre Montplaisir
 */
public final class ContextInfoManager {

	private static final String SHARED_LIBRARY_NAME = "lttng-ust-context-jni";

	private static final Pattern VALID_CONTEXT_NAME_PATTERN = Pattern.compile("^[a-zA-Z0-9_\\.]+$");

	private static ContextInfoManager instance;

	private final Map<String, IContextInfoRetriever> contextInfoRetrievers = new ConcurrentHashMap<String, IContextInfoRetriever>();
	private final Map<String, Long> contextInforRetrieverRefs = new HashMap<String, Long>();

	/**
	 * Lock used to keep the two maps above in sync when retrievers are
	 * registered or unregistered.
	 */
	private final Object retrieverLock = new Object();

	/** Singleton class, constructor should not be accessed directly */
	private ContextInfoManager() {
	}

	/**
	 * Get the singleton instance.
	 *
	 * <p>
	 * Usage of this class requires the "liblttng-ust-context-jni.so" native
	 * library to be present on the system and available (passing
	 * -Djava.library.path=path to the JVM may be needed).
	 * </p>
	 *
	 * @return The singleton instance
	 * @throws IOException
	 *             If the shared library cannot be found.
	 * @throws SecurityException
	 *             We will forward any SecurityExcepion that may be thrown when
	 *             trying to load the JNI library.
	 */
	public static synchronized ContextInfoManager getInstance() throws IOException, SecurityException {
		if (instance == null) {
			try {
				System.loadLibrary(SHARED_LIBRARY_NAME);
			} catch (UnsatisfiedLinkError e) {
				throw new IOException(e);
			}
			instance = new ContextInfoManager();
		}
		return instance;
	}

	/**
	 * Register a new context info retriever.
	 *
	 * <p>
	 * Each context info retriever is registered with a given "retriever name",
	 * which specifies the namespace of the context elements. This name is
	 * specified separately from the retriever objects, which would allow
	 * register the same retriever under different namespaces for example.
	 * </p>
	 *
	 * <p>
	 * If the method returns false (indicating registration failure), then the
	 * retriever object will *not* be used for context information.
	 * </p>
	 *
	 * @param retrieverName
	 *            The name to register to the context retriever object with.
	 * @param contextInfoRetriever
	 *            The context info retriever to register
	 * @return True if the retriever was successfully registered, false if there
	 *         was an error, for example if a retriever is already registered
	 *         with that name.
	 */
	public boolean registerContextInfoRetriever(String retrieverName, IContextInfoRetriever contextInfoRetriever) {
		synchronized (retrieverLock) {
			if (!validateRetrieverName(retrieverName)) {
				return false;
			}

			if (contextInfoRetrievers.containsKey(retrieverName)) {
				/*
				 * There is already a retriever registered with that name,
				 * refuse the new registration.
				 */
				return false;
			}
			/*
			 * Inform LTTng-UST of the new retriever. The names have to start
			 * with "$app." on the UST side!
			 */
			long ref = LttngContextApi.registerProvider("$app." + retrieverName);
			if (ref == 0) {
				return false;
			}

			contextInfoRetrievers.put(retrieverName, contextInfoRetriever);
			contextInforRetrieverRefs.put(retrieverName, Long.valueOf(ref));

			return true;
		}
	}

	/**
	 * Unregister a previously added context info retriever.
	 *
	 * This method has no effect if the retriever was not already registered.
	 *
	 * @param retrieverName
	 *            The context info retriever to unregister
	 * @return True if unregistration was successful, false if there was an
	 *         error
	 */
	public boolean unregisterContextInfoRetriever(String retrieverName) {
		synchronized (retrieverLock) {
			if (!contextInfoRetrievers.containsKey(retrieverName)) {
				/*
				 * There was no retriever registered with that name.
				 */
				return false;
			}
			contextInfoRetrievers.remove(retrieverName);
			long ref = contextInforRetrieverRefs.remove(retrieverName).longValue();

			/* Unregister the retriever on the UST side too */
			LttngContextApi.unregisterProvider(ref);

			return true;
		}
	}

	/**
	 * Return the context info retriever object registered with the given name.
	 *
	 * @param retrieverName
	 *            The retriever name to look for
	 * @return The corresponding retriever object, or <code>null</code> if there
	 *         was none
	 */
	public IContextInfoRetriever getContextInfoRetriever(String retrieverName) {
		/*
		 * Note that this method does not take the retrieverLock, it lets
		 * concurrent threads access the ConcurrentHashMap directly.
		 *
		 * It's fine for a get() to happen during a registration or
		 * unregistration, it's first-come-first-serve.
		 */
		return contextInfoRetrievers.get(retrieverName);
	}

	/**
	 * Validate that the given retriever name contains only the allowed
	 * characters, which are alphanumerical characters, period "." and
	 * underscore "_". The name must also not start with a number.
	 */
	private static boolean validateRetrieverName(String contextName) {
		if (contextName.isEmpty()) {
			return false;
		}

		/* First character must not be a number */
		if (Character.isDigit(contextName.charAt(0))) {
			return false;
		}

		/* Validate the other characters of the string */
		Matcher matcher = VALID_CONTEXT_NAME_PATTERN.matcher(contextName);
		return matcher.matches();
	}
}
