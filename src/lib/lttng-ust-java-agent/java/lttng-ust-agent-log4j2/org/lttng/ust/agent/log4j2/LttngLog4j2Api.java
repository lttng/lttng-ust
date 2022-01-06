/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2016 EfficiOS Inc.
 * Copyright (C) 2016 Alexandre Montplaisir <alexmonthy@efficios.com>
 */

package org.lttng.ust.agent.log4j2;

/**
 * Virtual class containing the Java side of the LTTng-log4j JNI API methods.
 */
final class LttngLog4j2Api {

	private LttngLog4j2Api() {
	}

	static native void tracepointWithContext(String message, String loggerName, String className, String methodName,
			String fileName, int lineNumber, long timeStamp, int logLevel, String threadName, byte[] contextEntries,
			byte[] contextStrings);
}
