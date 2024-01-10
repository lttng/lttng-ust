<!--
SPDX-FileCopyrightText: 2010 Pierre-Marc Fournier <pierre-marc.fournier@polymtl.ca>

SPDX-License-Identifier: CC-BY-4.0
-->

This directory contains a simple API for instrumenting java applications.

Configuration examples to build this library:

dependency: openjdk-7-jdk

    ./configure --enable-jni-interface

Note that the OpenJDK 7 is used for development and continuous integration thus
we directly support that version for this library. However, it has been tested
with OpenJDK 6 also. Please let us know if other Java version (commercial or
not) work with this library.

After building, you can use the liblttng-ust-java.jar file in a Java project.
It requires the liblttng-ust-java.so* files (which get installed when doing
`make install') so make sure those are in the linker's library path.
