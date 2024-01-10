<!--
SPDX-FileCopyrightText: 2013 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>

SPDX-License-Identifier: CC-BY-4.0
-->

This is a demo application showing how to trace formatted strings into
LTTng-UST.

The simplest command to trace the demo program are:

```
lttng create
lttng enable-event -u "lttng_ust_tracef:event"
lttng start
./demo-tracef
lttng stop
lttng view
lttng destroy
```

The resulting lttng view output should look like this:

```
[07:32:02.021045683] (+?.?????????) thinkos lttng_ust:tracef: { cpu_id = 2 }, { _msg_length = 46, msg = "This is a "mystring test" formatted 0 event 42" }
[07:32:02.021062328] (+0.000016645) thinkos lttng_ust:tracef: { cpu_id = 2 }, { _msg_length = 46, msg = "This is a "mystring test" formatted 1 event 42" }
[07:32:02.021066300] (+0.000003972) thinkos lttng_ust:tracef: { cpu_id = 2 }, { _msg_length = 46, msg = "This is a "mystring test" formatted 2 event 42" }
[07:32:02.021069507] (+0.000003207) thinkos lttng_ust:tracef: { cpu_id = 2 }, { _msg_length = 46, msg = "This is a "mystring test" formatted 3 event 42" }
[07:32:02.021072541] (+0.000003034) thinkos lttng_ust:tracef: { cpu_id = 2 }, { _msg_length = 46, msg = "This is a "mystring test" formatted 4 event 42" }
```
