/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2017 EfficiOS Inc.
 * Copyright (C) 2017 Philippe Proulx <pproulx@efficios.com>
 */

package org.lttng.ust.agent;

import java.util.regex.Pattern;

/**
 * Class encapsulating an event name from the session daemon, and its
 * corresponding {@link Pattern}. This allows referring back to the original
 * event name, for example when we receive a disable command.
 *
 * @author Philippe Proulx
 * @author Alexandre Montplaisir
 */
class EventNamePattern {

	private final String originalEventName;

	/*
	 * Note that two Patterns coming from the exact same String will not be
	 * equals()! As such, it would be confusing to make the pattern part of this
	 * class's equals/hashCode
	 */
	private final transient Pattern pattern;

	public EventNamePattern(String eventName) {
		if (eventName == null) {
			throw new IllegalArgumentException();
		}

		originalEventName = eventName;
		pattern = patternFromEventName(eventName);
	}

	public String getEventName() {
		return originalEventName;
	}

	public Pattern getPattern() {
		return pattern;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + originalEventName.hashCode();
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
		EventNamePattern other = (EventNamePattern) obj;
		if (!originalEventName.equals(other.originalEventName)) {
			return false;
		}
		return true;
	}

	private static Pattern patternFromEventName(String eventName) {
		/*
		 * The situation here is that `\*` means a literal `*` in the event
		 * name, and `*` is a wildcard star. We check the event name one
		 * character at a time and create a list of tokens to be converter to
		 * partial patterns.
		 */
		StringBuilder bigBuilder = new StringBuilder("^");
		StringBuilder smallBuilder = new StringBuilder();

		for (int i = 0; i < eventName.length(); i++) {
			char c = eventName.charAt(i);

			switch (c) {
			case '*':
				/* Add current quoted builder's string if not empty. */
				if (smallBuilder.length() > 0) {
					bigBuilder.append(Pattern.quote(smallBuilder.toString()));
					smallBuilder.setLength(0);
				}

				/* Append the equivalent regex which is `.*`. */
				bigBuilder.append(".*");
				continue;

			case '\\':
				/* We only escape `*` and `\` here. */
				if (i < (eventName.length() - 1)) {
					char nextChar = eventName.charAt(i + 1);

					if (nextChar == '*' || nextChar == '\\') {
						smallBuilder.append(nextChar);
					} else {
						smallBuilder.append(c);
						smallBuilder.append(nextChar);
					}

					i++;
					continue;
				}
				break;

			default:
				break;
			}

			smallBuilder.append(c);
		}

		/* Add current quoted builder's string if not empty. */
		if (smallBuilder.length() > 0) {
			bigBuilder.append(Pattern.quote(smallBuilder.toString()));
		}

		bigBuilder.append("$");

		return Pattern.compile(bigBuilder.toString());
	}
}
