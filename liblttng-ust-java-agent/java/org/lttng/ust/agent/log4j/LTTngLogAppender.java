/*
 * Copyright (C) 2014 - Christian Babeux <christian.babeux@efficios.com>
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

import java.lang.String;

import org.apache.log4j.AppenderSkeleton;
import org.apache.log4j.spi.LoggingEvent;

class LTTngLogAppender extends AppenderSkeleton {

	private Boolean isRoot;

	public LTTngLogAppender(Boolean isRoot) {
		super();
		this.isRoot = isRoot;
		try {
			System.loadLibrary("lttng-ust-log4j-jni"); //$NON-NLS-1$
		} catch (SecurityException e) {
			e.printStackTrace();
		} catch (UnsatisfiedLinkError e) {
			e.printStackTrace();
		} catch (NullPointerException e) {
			/* Should never happen */
			e.printStackTrace();
		}
	}

	public Boolean isRoot() {
		return this.isRoot;
	}

	@Override
	protected void append(LoggingEvent event) {
		int line;

		/*
		 * The line number returned from LocationInformation is a
		 * string. At least try to convert to a proper int.
		 */
		try {
			String lineString = event.getLocationInformation().getLineNumber();
			line = Integer.parseInt(lineString);
		} catch (NumberFormatException n) {
			line = -1;
		}

		if (this.isRoot) {
			tracepointS(event.getRenderedMessage(),
					event.getLoggerName(),
					event.getLocationInformation().getClassName(),
					event.getLocationInformation().getMethodName(),
					event.getLocationInformation().getFileName(),
					line,
					event.getTimeStamp(),
					event.getLevel().toInt(),
					event.getThreadName());
		} else {
			tracepointU(event.getRenderedMessage(),
					event.getLoggerName(),
					event.getLocationInformation().getClassName(),
					event.getLocationInformation().getMethodName(),
					event.getLocationInformation().getFileName(),
					line,
					event.getTimeStamp(),
					event.getLevel().toInt(),
					event.getThreadName());
		}
	}

	@Override
	public void close() {}

	@Override
	public boolean requiresLayout() {
		return false;
	}

	/* Use for a user session daemon. */
	private native void tracepointU(String msg,
					String logger_name,
					String class_name,
					String method_name,
					String file_name,
					int line_number,
					long timestamp,
					int loglevel,
					String thread_name);

	/* Use for a root session daemon. */
	private native void tracepointS(String msg,
					String logger_name,
					String class_name,
					String method_name,
					String file_name,
					int line_number,
					long timestamp,
					int loglevel,
					String thread_name);
}
