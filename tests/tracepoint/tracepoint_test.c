/* Copyright (C) 2010 David Goulet <david.goulet@polymtl.ca>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA
 */

/*
 * This test is aimed at testing tracepoint *with* ust_marker :
 *
 * 1) tracepoint named : "ust_event"
 * 	-) Probe 1 registered and recording the value 13 (x5)
 * 	-) Probe 2 registered and recording the value 42 (x5)
 * 	-) Probe 3 registered and recording the payload of the struct message
 * 	but using a *different* tracepoint (event_msg)
 *
 * 2) tracepoint named : "ust_event2"
 * 	-) Probe 4 registered and recording the value 42 (x100)
 */

#include <stdio.h>
#include <ust/marker.h>
#include "tracepoint_test.h"

DEFINE_TRACEPOINT(ust_event);
DEFINE_TRACEPOINT(ust_event2);

static struct message msg_probe3 = {
	.payload = "probe3",
};

/*
 * Probe 4 --> ust_event2
 * 	Will record 100 times the value 42
 */
void tp_probe4(void *data, unsigned int p4)
{
	int i;
	for (i = 0; i < 100; i++) {
		ust_marker_tp(event2, ust_event2, tp_probe4, "probe4 %u", p4);
	}
}

/*
 * Probe 3 --> ust_event *and* event_msg (from inside)
 * 	Will record the payload of msg_prob3 struct
 * 	from the data pointer of the probe
 */
void tp_probe3(void *data, unsigned int p3)
{
	struct message *msg;
	msg = (struct message*) data;
	ust_marker_tp(event_msg, ust_event_msg,
			tp_probe3, "probe %s", msg->payload);
}

/*
 * Probe 2 --> ust_event
 * 	Will record 5 times the number 13
 */
void tp_probe2(void *data, unsigned int p2)
{
	int i;
	for (i = 0; i < 5; i++) {
		ust_marker_tp(event, ust_event, tp_probe2, "probe %u", 13);
	}
}

/*
 * Probe 1 --> ust_event
 * 	Will record 5 times the unsigned int v = 42
 */
void tp_probe(void *data, unsigned int p1)
{
	int i;
	for (i = 0; i < 5; i++) {
		ust_marker_tp(event, ust_event, tp_probe, "probe %u", p1);
	}
}

static void __attribute__((constructor)) init()
{
	register_tracepoint(ust_event, tp_probe, NULL);
	register_tracepoint(ust_event, tp_probe2, NULL);
	register_tracepoint(ust_event, tp_probe3, &msg_probe3);
	register_tracepoint(ust_event2, tp_probe4, NULL);
}

int main(int argc, char **argv) {
	unsigned int v = 42;
	/* Tracepoint 1 : ust_event */
	tracepoint(ust_event, v);
	/* Tracepoint 2 : ust_event2 */
	tracepoint(ust_event2, v);

	return 0;
}
