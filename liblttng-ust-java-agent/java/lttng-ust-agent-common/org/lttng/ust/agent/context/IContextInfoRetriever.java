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
