/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2016 EfficiOS Inc.
 * Copyright (C) 2016 Alexandre Montplaisir <alexmonthy@efficios.com>
 */

package org.lttng.ust.agent.jul;

/**
 * Virtual class containing the Java side of the LTTng-JUL JNI API methods.
 *
 * @author Alexandre Montplaisir
 */
final class LttngJulApi {

	private LttngJulApi() {}

	static native void tracepoint(String msg,
			String logger_name,
			String class_name,
			String method_name,
			long millis,
			int log_level,
			int thread_id);

	static native void tracepointWithContext(String msg,
			String logger_name,
			String class_name,
			String method_name,
			long millis,
			int log_level,
			int thread_id,
			byte[] contextEntries,
			byte[] contextStrings);
}
