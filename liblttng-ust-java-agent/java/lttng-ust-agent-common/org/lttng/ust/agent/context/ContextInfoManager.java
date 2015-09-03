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

import java.util.Set;
import java.util.concurrent.CopyOnWriteArraySet;

/**
 * The singleton manager of {@link IContextInfoRetriever} objects.
 *
 * @author Alexandre Montplaisir
 */
public final class ContextInfoManager {

	private static final ContextInfoManager INSTANCE = new ContextInfoManager();

	private final Set<IContextInfoRetriever> cirs = new CopyOnWriteArraySet<IContextInfoRetriever>();

	/** Singleton class, constructor should not be accessed directly */
	private ContextInfoManager() {
	}

	/**
	 * Get the singleton instance.
	 *
	 * @return The singleton instance
	 * @deprecated The context-retrieving facilities are not yet implemented.
	 */
	@Deprecated
	public static ContextInfoManager getInstance() {
		return INSTANCE;
	}

	/**
	 * Register a new context info retriever.
	 *
	 * This method has no effect if the exact same retriever is already
	 * registered.
	 *
	 * @param cir
	 *            The context info retriever to register
	 */
	public void addContextInfoRetriever(IContextInfoRetriever cir) {
		cirs.add(cir);
	}

	/**
	 * Unregister a previously added context info retriever.
	 *
	 * This method has no effect if the retriever was not already registered.
	 *
	 * @param cir
	 *            The context info retriever to unregister
	 */
	public void removeContextInfoRetriever(IContextInfoRetriever cir) {
		cirs.remove(cir);
	}

	/**
	 * Return a read-only view (does not support
	 * {@link java.util.Iterator#remove}) of the currently registered context
	 * info retrievers.
	 *
	 * @return The current context info retrievers
	 */
	public Iterable<IContextInfoRetriever> getContextInfoRetrievers() {
		return cirs;
	}
}
