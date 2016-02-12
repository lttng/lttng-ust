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

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.Charset;
import java.util.Collection;
import java.util.Map;

import org.lttng.ust.agent.utils.LttngUstAgentLogger;

/**
 * This class is used to serialize the list of "context info" objects to pass
 * through JNI.
 *
 * The protocol expects two byte array parameters, which are contained here in
 * the {@link SerializedContexts} inner class.
 *
 * The first byte array is called the "entries array", and contains fixed-size
 * entries, one per context element.
 *
 * The second one is the "strings array", it is of variable length and used to
 * hold the variable-length strings. Each one of these strings is formatted as a
 * UTF-8 C-string, meaning in will end with a "\0" byte to indicate its end.
 * Entries in the first array may refer to offsets in the second array to point
 * to relevant strings.
 *
 * The fixed-size entries in the entries array contain the following elements
 * (size in bytes in parentheses):
 *
 * <ul>
 * <li>The offset in the strings array pointing to the full context name, like
 * "$app.myprovider:mycontext" (4)</li>
 * <li>The context value type (1)</li>
 * <li>The context value itself (8)</li>
 * </ul>
 *
 * The context value type will indicate how many bytes are used for the value.
 * If the it is of String type, then we use 4 bytes to represent the offset in
 * the strings array.
 *
 * So the total size of each entry is 13 bytes. All unused bytes (for context
 * values shorter than 8 bytes for example) will be zero'ed.
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

	/**
	 * Class used to wrap the two byte arrays returned by
	 * {@link #queryAndSerializeRequestedContexts}.
	 */
	public static class SerializedContexts {

		private final byte[] contextEntries;
		private final byte[] contextStrings;

		/**
		 * Constructor
		 *
		 * @param entries
		 *            Arrays for the fixed-size context entries.
		 * @param strings
		 *            Arrays for variable-length strings
		 */
		public SerializedContexts(byte[] entries, byte[] strings) {
			contextEntries = entries;
			contextStrings = strings;
		}

		/**
		 * @return The entries array
		 */
		public byte[] getEntriesArray() {
			return contextEntries;
		}

		/**
		 * @return The strings array
		 */
		public byte[] getStringsArray() {
			return contextStrings;
		}
	}

	private static final String UST_APP_CTX_PREFIX = "$app.";
	private static final int ENTRY_LENGTH = 13;
	private static final ByteOrder NATIVE_ORDER = ByteOrder.nativeOrder();
	private static final Charset UTF8_CHARSET = Charset.forName("UTF-8");
	private static final SerializedContexts EMPTY_CONTEXTS = new SerializedContexts(new byte[0], new byte[0]);

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
	public static SerializedContexts queryAndSerializeRequestedContexts(Collection<Map.Entry<String, Map<String, Integer>>> enabledContexts) {
		if (enabledContexts.isEmpty()) {
			/* Early return if there is no requested context information */
			return EMPTY_CONTEXTS;
		}

		ContextInfoManager contextManager;
		try {
			contextManager = ContextInfoManager.getInstance();
		} catch (IOException e) {
			/*
			 * The JNI library is not available, do not send any context
			 * information. No retriever could have been defined anyways.
			 */
			return EMPTY_CONTEXTS;
		}

		/* Compute the total number of contexts (flatten the map) */
		int totalArraySize = 0;
		for (Map.Entry<String, Map<String, Integer>> contexts : enabledContexts) {
			totalArraySize += contexts.getValue().size() * ENTRY_LENGTH;
		}

		/* Prepare the ByteBuffer that will generate the "entries" array */
		ByteBuffer entriesBuffer = ByteBuffer.allocate(totalArraySize);
		entriesBuffer.order(NATIVE_ORDER);
		entriesBuffer.clear();

		/* Prepare the streams that will generate the "strings" array */
		ByteArrayOutputStream stringsBaos = new ByteArrayOutputStream();
		DataOutputStream stringsDos = new DataOutputStream(stringsBaos);

		try {
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
						 * indicate the retriever does not supply this context.
						 * We will still write this information so that the
						 * tracer can know about it.
						 */
					}

					/* Serialize the result to the buffers */
					// FIXME Eventually pass the retriever name only once?
					String fullContextName = (UST_APP_CTX_PREFIX + requestedRetrieverName + ':' + requestedContext);
					byte[] strArray = fullContextName.getBytes(UTF8_CHARSET);

					entriesBuffer.putInt(stringsDos.size());
					stringsDos.write(strArray);
					stringsDos.writeChar('\0');

					LttngUstAgentLogger.log(ContextInfoSerializer.class,
							"ContextInfoSerializer: Context to be sent through JNI: " + fullContextName + '=' +
									(contextInfo == null ? "null" : contextInfo.toString()));

					serializeContextInfo(entriesBuffer, stringsDos, contextInfo);
				}
			}

			stringsDos.flush();
			stringsBaos.flush();

		} catch (IOException e) {
			/*
			 * Should not happen because we are wrapping a
			 * ByteArrayOutputStream, which writes to memory
			 */
			e.printStackTrace();
		}

		byte[] entriesArray = entriesBuffer.array();
		byte[] stringsArray = stringsBaos.toByteArray();
		return new SerializedContexts(entriesArray, stringsArray);
	}

	private static final int CONTEXT_VALUE_LENGTH = 8;

	private static void serializeContextInfo(ByteBuffer entriesBuffer, DataOutputStream stringsDos, Object contextInfo) throws IOException {
		int remainingBytes;
		if (contextInfo == null) {
			entriesBuffer.put(DataType.NULL.getValue());
			remainingBytes = CONTEXT_VALUE_LENGTH;

		} else if (contextInfo instanceof Integer) {
			entriesBuffer.put(DataType.INTEGER.getValue());
			entriesBuffer.putInt(((Integer) contextInfo).intValue());
			remainingBytes = CONTEXT_VALUE_LENGTH - 4;

		} else if (contextInfo instanceof Long) {
			entriesBuffer.put(DataType.LONG.getValue());
			entriesBuffer.putLong(((Long) contextInfo).longValue());
			remainingBytes = CONTEXT_VALUE_LENGTH - 8;

		} else if (contextInfo instanceof Double) {
			entriesBuffer.put(DataType.DOUBLE.getValue());
			entriesBuffer.putDouble(((Double) contextInfo).doubleValue());
			remainingBytes = CONTEXT_VALUE_LENGTH - 8;

		} else if (contextInfo instanceof Float) {
			entriesBuffer.put(DataType.FLOAT.getValue());
			entriesBuffer.putFloat(((Float) contextInfo).floatValue());
			remainingBytes = CONTEXT_VALUE_LENGTH - 4;

		} else if (contextInfo instanceof Byte) {
			entriesBuffer.put(DataType.BYTE.getValue());
			entriesBuffer.put(((Byte) contextInfo).byteValue());
			remainingBytes = CONTEXT_VALUE_LENGTH - 1;

		} else if (contextInfo instanceof Short) {
			entriesBuffer.put(DataType.SHORT.getValue());
			entriesBuffer.putShort(((Short) contextInfo).shortValue());
			remainingBytes = CONTEXT_VALUE_LENGTH - 2;

		} else if (contextInfo instanceof Boolean) {
			entriesBuffer.put(DataType.BOOLEAN.getValue());
			boolean b = ((Boolean) contextInfo).booleanValue();
			/* Converted to one byte, write 1 for true, 0 for false */
			entriesBuffer.put((byte) (b ? 1 : 0));
			remainingBytes = CONTEXT_VALUE_LENGTH - 1;

		} else {
			/* Also includes the case of Character. */
			/*
			 * We'll write the object as a string, into the strings array. We
			 * will write the corresponding offset to the entries array.
			 */
			String str = contextInfo.toString();
			byte[] strArray = str.getBytes(UTF8_CHARSET);

			entriesBuffer.put(DataType.STRING.getValue());

			entriesBuffer.putInt(stringsDos.size());
			stringsDos.write(strArray);
			stringsDos.writeChar('\0');

			remainingBytes = CONTEXT_VALUE_LENGTH - 4;
		}
		entriesBuffer.position(entriesBuffer.position() + remainingBytes);
	}
}
