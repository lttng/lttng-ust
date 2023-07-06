<!--
SPDX-FileCopyrightText: 2023 EfficiOS, Inc.

SPDX-License-Identifier: CC-BY-4.0
-->

# LTTng-UST libc wrapper

`liblttng-ust-libc` is used for instrumenting some calls to libc in a program,
without need for recompiling it.

This library defines a `malloc()` function that is instrumented with a
tracepoint. It also calls the libc `malloc()` afterwards. When loaded with
LD\_PRELOAD, it replaces the libc `malloc()` function, in effect instrumenting
all calls to `malloc()`. The same is performed for `free()`.

See the "run" script for a usage example.
