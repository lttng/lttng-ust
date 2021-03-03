# -*- coding: utf-8 -*-
#
# SPDX-License-Identifier: LGPL-2.1-only
#
# Copyright (C) 2015 Philippe Proulx <pproulx@efficios.com>

from __future__ import unicode_literals

from .version import __version__
from .version import __soname_major__

# this creates the daemon threads and registers the application
import lttngust.agent
