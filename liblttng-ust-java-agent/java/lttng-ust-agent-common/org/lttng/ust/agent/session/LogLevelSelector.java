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

package org.lttng.ust.agent.session;

/**
 * Log level filtering element, which is part of an {@link EventRule}.
 *
 * @author Alexandre Montplaisir
 */
public class LogLevelSelector {

	/**
	 * The type of log level filter that is enabled.
	 *
	 * Defined from lttng-tools' include/lttng/event.h.
	 */
	public enum LogLevelType {
		/**
		 * All log levels are enabled. This overrides the value of
		 * {@link LogLevelSelector#getLogLevel}.
		 */
		LTTNG_EVENT_LOGLEVEL_ALL(0),

		/** This log level along with all log levels of higher severity are enabled. */
		LTTNG_EVENT_LOGLEVEL_RANGE(1),

		/** Only this exact log level is enabled. */
		LTTNG_EVENT_LOGLEVEL_SINGLE(2);

		private final int value;

		private LogLevelType(int value) {
			this.value = value;
		}

		/**
		 * Get the numerical (int) value representing this log level type in the
		 * communication protocol.
		 *
		 * @return The int value
		 */
		public int getValue() {
			return value;
		}

		static LogLevelType fromValue(int val) {
			switch (val) {
			case 0:
				return LTTNG_EVENT_LOGLEVEL_ALL;
			case 1:
				return LTTNG_EVENT_LOGLEVEL_RANGE;
			case 2:
				return LTTNG_EVENT_LOGLEVEL_SINGLE;
			default:
				throw new IllegalArgumentException();
			}
		}
	}

	private final int logLevel;
	private final LogLevelType logLevelType;

	/**
	 * Constructor using numerical values straight from the communication
	 * protocol.
	 *
	 * @param logLevel
	 *            The numerical value of the log level. The exact value depends
	 *            on the tracing domain, see include/lttng/event.h in the
	 *            lttng-tools tree for the complete enumeration.
	 * @param logLevelType
	 *            The numerical value of the log level type. It will be
	 *            converted to a {@link LogLevelType} by this constructor.
	 * @throws IllegalArgumentException
	 *             If the 'logLevelType' does not correspond to a valid value.
	 */
	public LogLevelSelector(int logLevel, int logLevelType) {
		this.logLevel = logLevel;
		this.logLevelType = LogLevelType.fromValue(logLevelType);
	}

	/**
	 * "Manual" constructor, specifying the {@link LogLevelType} directly.
	 *
	 * @param logLevel
	 *            The numerical value of the log level. The exact value depends
	 *            on the tracing domain, see include/lttng/event.h in the
	 *            lttng-tools tree for the complete enumeration.
	 * @param type
	 *            The log level filter type.
	 */
	public LogLevelSelector(int logLevel, LogLevelType type) {
		this.logLevel = logLevel;
		this.logLevelType = type;
	}

	/**
	 * Get the numerical value of the log level element. Does not apply if
	 * {@link #getLogLevelType} returns
	 * {@link LogLevelType#LTTNG_EVENT_LOGLEVEL_ALL}.
	 *
	 * @return The numerical value of the log level
	 */
	public int getLogLevel() {
		return logLevel;
	}

	/**
	 * Get the log level filter type.
	 *
	 * @return The log level filter type
	 */
	public LogLevelType getLogLevelType() {
		return logLevelType;
	}

	/**
	 * Helper method to determine if an event with the given log level should be
	 * traced when considering this filter.
	 *
	 * For example, if this filter object represents "higher severity than 5",
	 * and the log level passed in parameter is "8", it will return that it
	 * matches (higher value means higher severity).
	 *
	 * @param targetLogLevel
	 *            The log level value of the event to check for
	 * @return Should this event be traced, or not
	 */
	public boolean matches(int targetLogLevel) {
		switch (logLevelType) {
		case LTTNG_EVENT_LOGLEVEL_ALL:
			return true;
		case LTTNG_EVENT_LOGLEVEL_RANGE:
			return (targetLogLevel >= logLevel);
		case LTTNG_EVENT_LOGLEVEL_SINGLE:
			return (targetLogLevel == logLevel);
		default:
			throw new IllegalStateException();
		}
	}

	// ------------------------------------------------------------------------
	// Methods from Object
	// ------------------------------------------------------------------------

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + logLevel;
		result = prime * result + ((logLevelType == null) ? 0 : logLevelType.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		LogLevelSelector other = (LogLevelSelector) obj;

		if (logLevel != other.logLevel) {
			return false;
		}
		if (logLevelType != other.logLevelType) {
			return false;
		}
		return true;
	}

	@Override
	public String toString() {
		if (getLogLevelType() == LogLevelType.LTTNG_EVENT_LOGLEVEL_ALL) {
			return LogLevelType.LTTNG_EVENT_LOGLEVEL_ALL.toString();
		}
		return String.valueOf(getLogLevel()) + ", " + getLogLevelType().toString();
	}
}
