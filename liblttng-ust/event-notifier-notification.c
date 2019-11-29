/*
 * event-notifier-notification.c
 *
 * Copyright (C) 2020 Francis Deslauriers <francis.deslauriers@efficios.com>
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

#define _LGPL_SOURCE

#include <errno.h>
#include <lttng/ust-events.h>
#include <usterr-signal-safe.h>

#include "share.h"

void lttng_event_notifier_notification_send(
		struct lttng_event_notifier *event_notifier)
{
	/*
	 * We want this write to be atomic AND non-blocking, meaning that we
	 * want to write either everything OR nothing.
	 * According to `pipe(7)`, writes that are smaller that the `PIPE_BUF`
	 * value must be atomic, so we assert that the message we send is less
	 * than PIPE_BUF.
	 */
	struct lttng_ust_event_notifier_notification notif;
	ssize_t ret;

	assert(event_notifier);
	assert(event_notifier->group);
	assert(sizeof(notif) <= PIPE_BUF);

	notif.token = event_notifier->user_token;

	ret = patient_write(event_notifier->group->notification_fd, &notif,
		sizeof(notif));
	if (ret == -1) {
		if (errno == EAGAIN) {
			DBG("Cannot send event notifier notification without blocking: %s",
				strerror(errno));
		} else {
			DBG("Error to sending event notifier notification: %s",
				strerror(errno));
			abort();
		}
	}
}
