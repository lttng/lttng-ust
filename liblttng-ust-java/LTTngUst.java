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

package org.lttng.ust;

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
 *
 */
public abstract class LTTngUst {

    /**
     * Initialize the UST tracer. This should always be called first, before any
     * tracepoint* method.
     */
    public static void init() {
        System.loadLibrary("lttng-ust-java"); //$NON-NLS-1$
    }

    /**
     * Insert a tracepoint with a payload of type Integer.
     *
     * @param name
     *            The name assigned to this event. For best performance, this
     *            should be a statically-defined String, or a literal.
     * @param payload
     *            The int payload
     */
    public static native void tracepointInt(String name, int payload);

    /**
     * Insert a tracepoint with a payload consisting of two integers.
     *
     * @param name
     *            The name assigned to this event. For best performance, this
     *            should be a statically-defined String, or a literal.
     * @param payload1
     *            The first int payload
     * @param payload2
     *            The second int payload
     */
    public static native void
    tracepointIntInt(String name, int payload1, int payload2);

    /**
     * Insert a tracepoint with a payload of type Long
     *
     * @param name
     *            The name assigned to this event. For best performance, this
     *            should be a statically-defined String, or a literal.
     * @param payload
     *            The long payload
     */
    public static native void tracepointLong(String name, long payload);

    /**
     * Insert a tracepoint with a payload consisting of two longs.
     *
     * @param name
     *            The name assigned to this event. For best performance, this
     *            should be a statically-defined String, or a literal.
     * @param payload1
     *            The first long payload
     * @param payload2
     *            The second long payload
     */
    public static native void
    tracepointLongLong(String name, long payload1, long payload2);

    /**
     * Insert a tracepoint with a String payload.
     *
     * @param name
     *            The name assigned to this event. For best performance, this
     *            should be a statically-defined String, or a literal.
     * @param payload
     *            The String payload
     */
    public static native void tracepointString(String name, String payload);

}

