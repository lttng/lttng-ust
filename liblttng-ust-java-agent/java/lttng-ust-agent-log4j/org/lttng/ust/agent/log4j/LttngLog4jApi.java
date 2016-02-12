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

package org.lttng.ust.agent.log4j;

/**
 * Virtual class containing the Java side of the LTTng-log4j JNI API methods.
 *
 * @author Alexandre Montplaisir
 */
final class LttngLog4jApi {

	private LttngLog4jApi() {}

	static native void tracepoint(String msg,
			String logger_name,
			String class_name,
			String method_name,
			String file_name,
			int line_number,
			long timestamp,
			int loglevel,
			String thread_name);

	static native void tracepointWithContext(String msg,
			String logger_name,
			String class_name,
			String method_name,
			String file_name,
			int line_number,
			long timestamp,
			int loglevel,
			String thread_name,
			byte[] contextEntries,
			byte[] contextStrings);
}
