/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2015 EfficiOS Inc.
 * Copyright (C) 2015 Alexandre Montplaisir <alexmonthy@efficios.com>
 */

package org.lttng.ust.agent.context;

/**
 * Context-retrieving object specified by the application to extract
 * application-specific context information, which can then be passed on to the
 * Java agents and saved to a trace.
 *
 * Retriever objects should be registered to the {@link ContextInfoManager} to
 * make them available to the LTTng agents.
 *
 * @author Alexandre Montplaisir
 */
public interface IContextInfoRetriever {

	/**
	 * Retrieve a piece of context information from the application, identified
	 * by a key.
	 *
	 * @param key
	 *            The key identifying the context information
	 * @return The context information.
	 */
	Object retrieveContextInfo(String key);
}
