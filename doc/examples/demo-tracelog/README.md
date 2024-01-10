<!--
SPDX-FileCopyrightText: 2015 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>

SPDX-License-Identifier: CC-BY-4.0
-->

This is a demo application showing how to trace logging statements into
LTTng-UST.

The simplest commands to trace the demo program are:

```
lttng create
lttng enable-event -u "lttng_ust_tracelog:*"
lttng start
./demo-tracelog
lttng stop
lttng view
lttng destroy
```

The resulting lttng view output should look like this:

```
[15:54:19.454863179] (+?.?????????) thinkos lttng_ust_tracelog:TRACE_ERR: { cpu_id = 0 }, { line = 45, file = "demo-tracelog.c", func = "main", _msg_length = 17, msg = "Error condition 0" }
[15:54:19.454871660] (+0.000008481) thinkos lttng_ust_tracelog:TRACE_ERR: { cpu_id = 0 }, { line = 45, file = "demo-tracelog.c", func = "main", _msg_length = 17, msg = "Error condition 1" }
[15:54:19.454872838] (+0.000001178) thinkos lttng_ust_tracelog:TRACE_ERR: { cpu_id = 0 }, { line = 45, file = "demo-tracelog.c", func = "main", _msg_length = 17, msg = "Error condition 2" }
[15:54:19.454873541] (+0.000000703) thinkos lttng_ust_tracelog:TRACE_ERR: { cpu_id = 0 }, { line = 45, file = "demo-tracelog.c", func = "main", _msg_length = 17, msg = "Error condition 3" }
[15:54:19.454874283] (+0.000000742) thinkos lttng_ust_tracelog:TRACE_ERR: { cpu_id = 0 }, { line = 45, file = "demo-tracelog.c", func = "main", _msg_length = 17, msg = "Error condition 4" }
```
