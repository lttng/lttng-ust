<!--
SPDX-FileCopyrightText: 2013 Jérémie Galarneau <jeremie.galarneau@efficios.com>

SPDX-License-Identifier: CC-BY-4.0
-->

This is a demo application used to test the LTTng userspace tracer.

demo-trace shell script preloads the provider shared objects before
executing the demo. Executing "demo" without the shell wrapper will not
provide any tracing support. This ensures the demo binary can be
distributed on distros without depending on having liblttng-ust.so in
place. Note: the "demo" program must be compiled with "-ldl" on Linux,
with "-lc" on BSD.

The simplest command to trace the demo program are:
lttng create
lttng enable-event -u -a
lttng start
./demo-trace
lttng destroy

That will create a trace in your $HOME/lttng-traces directory.

The resulting babeltrace output should look like this:
[554297567999315] ust_tests_demo:starting: { 1 }, { value = 123 }
[554297568020834] ust_tests_demo2:loop: { 1 }, { intfield = 0, intfield2 = 0x0, longfield = 0, netintfield = 0, netintfieldhex = 0x0, arrfield1 = [ [0] = 1, [1] = 2, [2] = 3 ], arrfield2 = "test", _seqfield1_length = 4, seqfield1 = [ [0] = 116, [1] = 101, [2] = 115, [3] = 116 ], _seqfield2_length = 4, seqfield2 = "test", stringfield = "test", floatfield = 2222, doublefield = 2 }
[554297568024780] ust_tests_demo2:loop: { 1 }, { intfield = 1, intfield2 = 0x1, longfield = 1, netintfield = 1, netintfieldhex = 0x1, arrfield1 = [ [0] = 1, [1] = 2, [2] = 3 ], arrfield2 = "test", _seqfield1_length = 4, seqfield1 = [ [0] = 116, [1] = 101, [2] = 115, [3] = 116 ], _seqfield2_length = 4, seqfield2 = "test", stringfield = "test", floatfield = 2222, doublefield = 2 }
[554297568027050] ust_tests_demo2:loop: { 1 }, { intfield = 2, intfield2 = 0x2, longfield = 2, netintfield = 2, netintfieldhex = 0x2, arrfield1 = [ [0] = 1, [1] = 2, [2] = 3 ], arrfield2 = "test", _seqfield1_length = 4, seqfield1 = [ [0] = 116, [1] = 101, [2] = 115, [3] = 116 ], _seqfield2_length = 4, seqfield2 = "test", stringfield = "test", floatfield = 2222, doublefield = 2 }
[554297568029014] ust_tests_demo2:loop: { 1 }, { intfield = 3, intfield2 = 0x3, longfield = 3, netintfield = 3, netintfieldhex = 0x3, arrfield1 = [ [0] = 1, [1] = 2, [2] = 3 ], arrfield2 = "test", _seqfield1_length = 4, seqfield1 = [ [0] = 116, [1] = 101, [2] = 115, [3] = 116 ], _seqfield2_length = 4, seqfield2 = "test", stringfield = "test", floatfield = 2222, doublefield = 2 }
[554297568030861] ust_tests_demo2:loop: { 1 }, { intfield = 4, intfield2 = 0x4, longfield = 4, netintfield = 4, netintfieldhex = 0x4, arrfield1 = [ [0] = 1, [1] = 2, [2] = 3 ], arrfield2 = "test", _seqfield1_length = 4, seqfield1 = [ [0] = 116, [1] = 101, [2] = 115, [3] = 116 ], _seqfield2_length = 4, seqfield2 = "test", stringfield = "test", floatfield = 2222, doublefield = 2 }
[554297568033138] ust_tests_demo:done: { 1 }, { value = 456 }
[554297568034533] ust_tests_demo3:done: { 1 }, { value = 42 }
