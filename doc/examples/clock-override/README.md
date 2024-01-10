<!--
SPDX-FileCopyrightText: 2014 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>

SPDX-License-Identifier: CC-BY-4.0
-->

This clock override example shows how to implement and load a clock
override plugin for LTTng-UST. This can be useful in cases where direct
hardware access is available for architecture-specific clocks, and where
it should be used rather than the Linux kernel Monotonic clock.

When using LTTng-tools keep in mind that lttng-sessiond uses lttng-ust's clock
definition and functions. Thus `LTTNG_UST_CLOCK_PLUGIN` needs to be defined
when launching lttng-sessiond.
