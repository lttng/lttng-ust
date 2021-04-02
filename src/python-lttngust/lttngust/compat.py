# -*- coding: utf-8 -*-
# SPDX-License-Identifier: LGPL-2.1-only
#
# Copyright (C) 2020 Jonathan Rajotte <jonathan.rajotte-julien@efficios.com>

import sys
import time


# Support for deprecation of time.clock().
# Deprecated since python 3.3 and removed in python 3.8.
# See PEP 418 for more details.
def _clock():
    if sys.version_info > (3,2):
        clock = time.perf_counter()
    else:
        clock = time.clock()
    return clock
