/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2016 EfficiOS Inc.
 * Copyright (C) 2016 Alexandre Montplaisir <alexmonthy@efficios.com>
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
