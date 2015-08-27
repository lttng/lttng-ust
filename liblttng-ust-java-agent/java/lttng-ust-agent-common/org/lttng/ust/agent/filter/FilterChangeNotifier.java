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

package org.lttng.ust.agent.filter;

import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import org.lttng.ust.agent.session.EventRule;

/**
 * Singleton class managing the filter notifications.
 *
 * Applications can register a {@link IFilterChangeListener} to be notified when
 * event filtering rules change in the tracing sessions.
 *
 * @author Alexandre Montplaisir
 */
public final class FilterChangeNotifier {

	/** Lazy-loaded singleton instance object */
	private static FilterChangeNotifier instance = null;

	private final Map<EventRule, Integer> enabledEventRules = new HashMap<EventRule, Integer>();
	private final Collection<IFilterChangeListener> registeredListeners = new LinkedList<IFilterChangeListener>();


	/**
	 * Private constructor, singleton class should not be instantiated directly.
	 */
	private FilterChangeNotifier() {
	}

	/**
	 * Get the singleton instance, initializing it if needed.
	 *
	 * @return The singleton instance
	 */
	public static synchronized FilterChangeNotifier getInstance() {
		if (instance == null) {
			instance = new FilterChangeNotifier();
		}
		return instance;
	}

	/**
	 * Notify the filter manager that a new rule was enabled in a tracing
	 * session ("lttng enable-event ...")
	 *
	 * This is meant to be called by the LTTng Agent only. External Java
	 * applications should not call this.
	 *
	 * @param rule
	 *            The rule that was added
	 */
	public synchronized void addEventRule(EventRule rule) {
		Integer count = enabledEventRules.get(rule);
		if (count == null) {
			/*
			 * This is the first instance of this rule being enabled. Add it to
			 * the map and send notifications to the registered notifiers.
			 */
			enabledEventRules.put(rule, Integer.valueOf(1));
			notifyForAddedRule(rule);
			return;
		}
		if (count.intValue() <= 0) {
			/* It should not have been in the map! */
			throw new IllegalStateException();
		}
		/*
		 * This exact event rule was already enabled, just increment its
		 * refcount without sending notifications
		 */
		enabledEventRules.put(rule, Integer.valueOf(count.intValue() + 1));
	}

	/**
	 * Notify the filter manager that an event name was disabled in the tracing
	 * sessions ("lttng disable-event ...").
	 *
	 * The "disable-event" only specifies an event name. This means all the
	 * rules containing this event name are to be disabled.
	 *
	 * This is meant to be called by the LTTng Agent only. External Java
	 * applications should not call this.
	 *
	 * @param eventName
	 *            The event name to disable
	 */
	public synchronized void removeEventRules(String eventName) {
		List<EventRule> rulesToRemove = new LinkedList<EventRule>();

		for (EventRule eventRule : enabledEventRules.keySet()) {
			if (eventRule.getEventName().equals(eventName)) {
				rulesToRemove.add(eventRule);
			}
		}
		/*
		 * We cannot modify the map while iterating on it. We have to do the
		 * removal separately from the iteration above.
		 */
		for (EventRule rule : rulesToRemove) {
			removeEventRule(rule);
		}
	}

	private synchronized void removeEventRule(EventRule eventRule) {
		Integer count = enabledEventRules.get(eventRule);
		if (count == null || count.intValue() <= 0) {
			/*
			 * We were asked us to disable an event rule that was not enabled
			 * previously. Command error?
			 */
			throw new IllegalStateException();
		}
		if (count.intValue() == 1) {
			/*
			 * This is the last instance of this event rule being disabled,
			 * remove it from the map and send notifications of this rule being
			 * gone.
			 */
			enabledEventRules.remove(eventRule);
			notifyForRemovedRule(eventRule);
			return;
		}
		/*
		 * Other sessions/daemons are still looking for this event rule, simply
		 * decrement its refcount, and do not send notifications.
		 */
		enabledEventRules.put(eventRule, Integer.valueOf(count.intValue() - 1));

	}

	/**
	 * Register a new listener to the manager.
	 *
	 * @param listener
	 *            The listener to add
	 */
	public synchronized void registerListener(IFilterChangeListener listener) {
		registeredListeners.add(listener);

		/* Send the current rules to the new listener ("statedump") */
		for (EventRule rule : enabledEventRules.keySet()) {
			listener.eventRuleAdded(rule);
		}
	}

	/**
	 * Unregister a listener from the manager.
	 *
	 * @param listener
	 *            The listener to remove
	 */
	public synchronized void unregisterListener(IFilterChangeListener listener) {
		registeredListeners.remove(listener);
	}

	private void notifyForAddedRule(final EventRule rule) {
		for (IFilterChangeListener notifier : registeredListeners) {
			notifier.eventRuleAdded(rule);
		}
	}

	private void notifyForRemovedRule(final EventRule rule) {
		for (IFilterChangeListener notifier : registeredListeners) {
			notifier.eventRuleRemoved(rule);
		}
	}
}
