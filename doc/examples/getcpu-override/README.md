<!--
SPDX-FileCopyrightText: 2014 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>

SPDX-License-Identifier: CC-BY-4.0
-->

This getcpu override example shows how to implement and load a getcpu
override plugin for LTTng-UST. This can be useful in cases where direct
hardware access is available for architecture-specific registers holding
the CPU number, and where it should be used rather than the Linux kernel
sched_getcpu() vDSO/syscall.
