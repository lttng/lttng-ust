<!--
SPDX-FileCopyrightText: 2023 EfficiOS, Inc.

SPDX-License-Identifier: CC-BY-4.0
-->

This directory contains the serialized ABI definitions for a typical build of
the lttng-ust libraries. This information is extracted using
[libabigail](https://sourceware.org/libabigail/).

The artefacts used to generate these were built with `CFLAGS="-O0 -ggdb"` and
all optional configure switches enabled.

You can compare the serialized ABI with a shared object to check for breaking
changes. For example, here we compare an in-tree built version of
`liblttng-ust.so` with the serialized ABI of stable-2.13 :

```
abidiff \
  extras/abi/2.13/x86_64-pc-linux-gnu/liblttng-ust.so.1.xml \
  src/lib/lttng-ust/.libs/liblttng-ust.so
```
