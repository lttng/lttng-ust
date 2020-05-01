/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2016 EfficiOS Inc.
 * Copyright (C) 2016 Alexandre Montplaisir <alexmonthy@efficios.com>
 */

package org.lttng.ust.agent.context;

/**
 * Virtual class containing the Java side of the LTTng-UST context provider
 * registering/unregistering methods.
 *
 * @author Alexandre Montplaisir
 */
final class LttngContextApi {

	private LttngContextApi() {}

	/**
	 * Register a context provider to UST.
	 *
	 * The callbacks are the same for all providers, and are defined in the .c
	 * file. The only needed information is the retriever (which is called
	 * "provider" from UST'S point of view) name.
	 *
	 * @param provider_name
	 *            The name of the provider
	 * @return The pointer to the created provider object. It's useless in the
	 *         Java space, but will be needed for
	 *         {@link #unregisterProvider(long)}.
	 */
	static native long registerProvider(String provider_name);

	/**
	 * Unregister a previously-registered context provider from UST.
	 *
	 * @param provider_ref
	 *            The pointer to the provider object, obtained from
	 *            {@link #registerProvider}
	 */
	static native void unregisterProvider(long provider_ref);
}

