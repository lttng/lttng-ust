/*
 * Copyright (C) 2016 - EfficiOS Inc., Alexandre Montplaisir <alexmonthy@efficios.com>
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

