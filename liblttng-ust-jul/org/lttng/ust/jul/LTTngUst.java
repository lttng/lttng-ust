/**
 * Copyright (C) 2011-2012 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 * Copyright (C) 2012 Alexandre Montplaisir <alexandre.montplaisir@polymtl.ca>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; only
 * version 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

package org.lttng.ust.jul;

/**
 * This class implements the the Java side of the LTTng-UST Java interface.
 *
 * First, make sure you have installed "liblttng-ust-java.so" where the linker
 * can find it. You can then call LTTngUst.init() from your Java program to
 * connect the methods exposed here to the native library.
 *
 * Because of limitations in the probe declaration, all trace events generated
 * by this library will have "lttng_ust_java" for domain, and "<type>_event" for
 * event name in the CTF trace files. The "name" parameter will instead appear
 * as the first element of the event's payload.
 *
 * @author Mathieu Desnoyers
 * @author Alexandre Montplaisir
 * @author David Goulet
 *
 */
public abstract class LTTngUst {
	/**
	 * Initialize the UST tracer. This should always be called first, before any
	 * tracepoint* method.
	 */
	public static void init() {
		System.loadLibrary("lttng-ust-jul-jni"); //$NON-NLS-1$
	}

	/**
	 * Insert a tracepoint for JUL event.
	 *
	 * @param msg
	 *            Raw message provided by the JUL API.
	 * @param logger_name
	 *            Logger name that trigger this event.
	 * @param class_name
	 *            Name of the class that (allegedly) issued the logging request.
	 * @param method_name
	 *            Name of the method that (allegedly) issued the logging request.
	 * @param millis
	 *            Event time in milliseconds since 1970.
	 * @param log_level
	 *            Log level of the event from JUL.
	 * @param thread_id
	 *            Identifier for the thread where the message originated.
	 */
    public static native void tracepoint(String msg, String logger_name, String class_name,
			String method_name, long millis, int log_level, int thread_id);
}
