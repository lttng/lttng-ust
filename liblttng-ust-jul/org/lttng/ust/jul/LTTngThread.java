/*
 * Copyright (C) 2013 - David Goulet <dgoulet@efficios.com>
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License, version 2.1 only,
 * as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
 * for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

package org.lttng.ust.jul;

import java.util.concurrent.Semaphore;

public class LTTngThread implements Runnable {
	private LTTngLogHandler handler;
	private LTTngTCPSessiondClient sessiondClient;

	public LTTngThread(String host, int port, LTTngLogHandler handler,
			Semaphore registerSem) {
		this.handler = handler;
		this.sessiondClient = new LTTngTCPSessiondClient(host, port,
				registerSem);
	}

	@Override
	public void run() {
		try {
			this.sessiondClient.init(this.handler);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public void dispose() {
		this.sessiondClient.destroy();
	}
}
