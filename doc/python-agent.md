<!--
SPDX-FileCopyrightText: 2015 Jonathan Rajotte <jonathan.rajotte-julien@efficios.com>

SPDX-License-Identifier: CC-BY-4.0
-->

# Using the python agent

To build the agent:

    $ ./configure --enable-python-agent

The configure script is set to look for the first python version >= 2.7.
To build the agent against another version of python:

    $ export PYTHON=<python path>
    $ ./configure --enable-python-agent
