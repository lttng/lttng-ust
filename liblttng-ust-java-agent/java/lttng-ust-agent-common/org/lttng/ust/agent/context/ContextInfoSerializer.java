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

package org.lttng.ust.agent.context;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.Charset;
import java.util.Collection;
import java.util.Map;

/**
 * This class is used to serialize the list of "context info" objects to pass
 * through JNI.
 *
 * The protocol expects a single byte array parameter. This byte array consists
 * of a series of fixed-size entries, where each entry contains the following
 * elements (with their size in bytes in parenthesis):
 *
 * <ul>
 * <li>The full context name, like "$app.myprovider:mycontext" (256)</li>
 * <li>The context value type (1)</li>
 * <li>The context value itself(256)</li>
 * </ul>
 *
 * So the total size of each entry is 513 bytes. All unused bytes will be
 * zero'ed.
 *
 * @author Alexandre Montplaisir
 */
public class ContextInfoSerializer {

	private enum DataType {
		NULL(0),
		INTEGER(1),
		LONG(2),
		DOUBLE(3),
		FLOAT(4),
		BYTE(5),
		SHORT(6),
		BOOLEAN(7),
		STRING(8);

		private final byte value;

		private DataType(int value) {
			this.value = (byte) value;
		}

		public byte getValue() {
			return value;
		}
	}

	private static final String UST_APP_CTX_PREFIX = "$app.";
	private static final int ELEMENT_LENGTH = 256;
	private static final int ENTRY_LENGTH = 513;
	private static final ByteOrder NATIVE_ORDER = ByteOrder.nativeOrder();
	private static final Charset UTF8_CHARSET = Charset.forName("UTF-8");
	private static final byte[] EMPTY_ARRAY = new byte[0];

	/**
	 * From the list of requested contexts in the tracing session, look them up
	 * in the {@link ContextInfoManager}, retrieve the available ones, and
	 * serialize them into a byte array.
	 *
	 * @param enabledContexts
	 *            The contexts that are enabled in the tracing session (indexed
	 *            first by retriever name, then by index names). Should come
	 *            from the LTTng Agent.
	 * @return The byte array representing the intersection of the requested and
	 *         available contexts.
	 */
	public static byte[] queryAndSerializeRequestedContexts(Collection<Map.Entry<String, Map<String, Integer>>> enabledContexts) {
		if (enabledContexts.isEmpty()) {
			/* Early return if there is no requested context information */
			return EMPTY_ARRAY;
		}

		/* Compute the total number of contexts (flatten the map) */
		int totalArraySize = 0;
		for (Map.Entry<String, Map<String, Integer>> contexts : enabledContexts) {
			totalArraySize += contexts.getValue().size() * ENTRY_LENGTH;
		}

		ContextInfoManager contextManager;
		try {
			contextManager = ContextInfoManager.getInstance();
		} catch (IOException e) {
			/*
			 * The JNI library is not available, do not send any context
			 * information. No retriever could have been defined anyways.
			 */
			return EMPTY_ARRAY;
		}

		ByteBuffer buffer = ByteBuffer.allocate(totalArraySize);
		buffer.order(NATIVE_ORDER);
		buffer.clear();

		for (Map.Entry<String, Map<String, Integer>> entry : enabledContexts) {
			String requestedRetrieverName = entry.getKey();
			Map<String, Integer> requestedContexts = entry.getValue();

			IContextInfoRetriever retriever = contextManager.getContextInfoRetriever(requestedRetrieverName);

			for (String requestedContext : requestedContexts.keySet()) {
				Object contextInfo;
				if (retriever == null) {
					contextInfo = null;
				} else {
					contextInfo = retriever.retrieveContextInfo(requestedContext);
					/*
					 * 'contextInfo' can still be null here, which would
					 * indicate the retriever does not supply this context. We
					 * will still write this information so that the tracer can
					 * know about it.
					 */
				}

				/* Serialize the result to the buffer */
				// FIXME Eventually pass the retriever name only once?
				String fullContextName = (UST_APP_CTX_PREFIX + requestedRetrieverName + ':' + requestedContext);
				byte[] strArray = fullContextName.getBytes(UTF8_CHARSET);
				int remainingBytes = ELEMENT_LENGTH - strArray.length;
				// FIXME Handle case where name is too long...
				buffer.put(strArray);
				buffer.position(buffer.position() + remainingBytes);

				serializeContextInfo(buffer, contextInfo);
			}
		}
		return buffer.array();
	}

	private static void serializeContextInfo(ByteBuffer buffer, Object contextInfo) {
		int remainingBytes;
		if (contextInfo == null) {
			buffer.put(DataType.NULL.getValue());
			remainingBytes = ELEMENT_LENGTH;

		} else if (contextInfo instanceof Integer) {
			buffer.put(DataType.INTEGER.getValue());
			buffer.putInt(((Integer) contextInfo).intValue());
			remainingBytes = ELEMENT_LENGTH - 4;

		} else if (contextInfo instanceof Long) {
			buffer.put(DataType.LONG.getValue());
			buffer.putLong(((Long) contextInfo).longValue());
			remainingBytes = ELEMENT_LENGTH - 8;

		} else if (contextInfo instanceof Double) {
			buffer.put(DataType.DOUBLE.getValue());
			buffer.putDouble(((Double) contextInfo).doubleValue());
			remainingBytes = ELEMENT_LENGTH - 8;

		} else if (contextInfo instanceof Float) {
			buffer.put(DataType.FLOAT.getValue());
			buffer.putFloat(((Float) contextInfo).floatValue());
			remainingBytes = ELEMENT_LENGTH - 4;

		} else if (contextInfo instanceof Byte) {
			buffer.put(DataType.BYTE.getValue());
			buffer.put(((Byte) contextInfo).byteValue());
			remainingBytes = ELEMENT_LENGTH - 1;

		} else if (contextInfo instanceof Short) {
			buffer.put(DataType.SHORT.getValue());
			buffer.putShort(((Short) contextInfo).shortValue());
			remainingBytes = ELEMENT_LENGTH - 2;

		} else if (contextInfo instanceof Boolean) {
			buffer.put(DataType.BOOLEAN.getValue());
			boolean b = ((Boolean) contextInfo).booleanValue();
			/* Converted to one byte, write 1 for true, 0 for false */
			buffer.put((byte) (b ? 1 : 0));
			remainingBytes = ELEMENT_LENGTH - 1;

		} else {
			/* We'll write the object as a string. Also includes the case of Character. */
			String str = contextInfo.toString();
			byte[] strArray = str.getBytes(UTF8_CHARSET);

			buffer.put(DataType.STRING.getValue());
			if (strArray.length >= ELEMENT_LENGTH) {
				/* Trim the string to the max allowed length */
				buffer.put(strArray, 0, ELEMENT_LENGTH);
				remainingBytes = 0;
			} else {
				buffer.put(strArray);
				remainingBytes = ELEMENT_LENGTH - strArray.length;
			}
		}
		buffer.position(buffer.position() + remainingBytes);
	}
}
