# -*- coding: utf-8 -*-
#
# SPDX-License-Identifier: LGPL-2.1-only
#
# Copyright (C) 2015 Philippe Proulx <pproulx@efficios.com>
# Copyright (C) 2014 David Goulet <dgoulet@efficios.com>

from __future__ import unicode_literals
import logging
import ctypes

from .version import __soname_major__

class _Handler(logging.Handler):
    _LIB_NAME = 'liblttng-ust-python-agent.so.' + __soname_major__

    def __init__(self):
        super(self.__class__, self).__init__(level=logging.NOTSET)
        self.setFormatter(logging.Formatter('%(asctime)s'))

        # will raise if library is not found: caller should catch
        self.agent_lib = ctypes.cdll.LoadLibrary(_Handler._LIB_NAME)

    def emit(self, record):
        self.agent_lib.py_tracepoint(self.format(record).encode(),
                                     record.getMessage().encode(),
                                     record.name.encode(),
                                     record.funcName.encode(),
                                     record.lineno, record.levelno,
                                     record.thread,
                                     record.threadName.encode())
