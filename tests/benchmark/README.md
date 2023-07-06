<!--
SPDX-FileCopyrightText: 2013 Zifei Tong <soariez@gmail.com>

SPDX-License-Identifier: CC-BY-4.0
-->

To run the benchmark:

    ./test_benchmark

You can specify the number of iterations, events and threads by setting
environment variables `ITERS`, `DURATION`, `NR_THREADS` respectively:

    ITERS=10 DURATION=20 NR_THREADS=4 ./test_benchmark

`NR_CPUS` can also be configured, but by default is based on the contents of
`/proc/cpuinfo`.
