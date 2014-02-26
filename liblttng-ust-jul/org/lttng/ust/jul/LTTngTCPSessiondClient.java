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
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.lang.Integer;
import java.io.IOException;
import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.DataInputStream;
import java.net.*;
import java.lang.management.ManagementFactory;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.Timer;
import java.util.TimerTask;
import java.util.logging.Logger;
import java.util.Collections;

class USTRegisterMsg {
	public static int pid;
}

public class LTTngTCPSessiondClient {
	/* Command header from the session deamon. */
	private LTTngSessiondCmd2_4.sessiond_hdr headerCmd =
		new LTTngSessiondCmd2_4.sessiond_hdr();

	private final String sessiondHost;
	private final int sessiondPort;
	private Socket sessiondSock;
	private boolean quit = false;

	private DataInputStream inFromSessiond;
	private DataOutputStream outToSessiond;

	private LTTngLogHandler handler;

	private Semaphore registerSem;

	private Timer eventTimer;
	private Set<LTTngEvent> enabledEventSet =
		Collections.synchronizedSet(new HashSet<LTTngEvent>());
	/*
	 * Map of Logger objects that have been enabled. They are indexed by name.
	 */
	private HashMap<String, Logger> enabledLoggers = new HashMap<String, Logger>();
	/* Timer delay at each 5 seconds. */
	private final static long timerDelay = 5 * 1000;
	private static boolean timerInitialized;

	public LTTngTCPSessiondClient(String host, int port, Semaphore sem) {
		this.sessiondHost = host;
		this.sessiondPort = port;
		this.registerSem = sem;
		this.eventTimer = new Timer();
		this.timerInitialized = false;
	}

	private void setupEventTimer() {
		if (this.timerInitialized) {
			return;
		}

		this.eventTimer.scheduleAtFixedRate(new TimerTask() {
			@Override
			public void run() {
				synchronized (enabledEventSet) {
					LTTngSessiondCmd2_4.sessiond_enable_handler enableCmd = new
						LTTngSessiondCmd2_4.sessiond_enable_handler();
					/*
					 * Modifying events in a Set will raise a
					 * ConcurrentModificationException. Thus, we remove an event
					 * and add its modified version to modifiedEvents when a
					 * modification is necessary.
					 */
					Set<LTTngEvent> modifiedEvents = new HashSet<LTTngEvent>();
					Iterator<LTTngEvent> it = enabledEventSet.iterator();

					while (it.hasNext()) {
						int ret;
						Logger logger;
						LTTngEvent event = it.next();

						/*
						 * Check if this Logger name has been enabled already. Note
						 * that in the case of "*", it's never added in that hash
						 * table thus the enable command does a lookup for each
						 * logger name in that hash table for the * case in order
						 * to make sure we don't enable twice the same logger
						 * because JUL apparently accepts that the *same*
						 * LogHandler can be added twice on a Logger object...
						 * don't ask...
						 */
						logger = enabledLoggers.get(event.name);
						if (logger != null) {
							continue;
						}

						/*
						 * Set to one means that the enable all event has been seen
						 * thus event from that point on must use loglevel for all
						 * events. Else the object has its own loglevel.
						 */
						if (handler.logLevelUseAll == 1) {
							it.remove();
							event.logLevel.level = handler.logLevelAll;
							event.logLevel.type = handler.logLevelTypeAll;
							modifiedEvents.add(event);
						}

						/*
						 * The all event is a special case since we have to iterate
						 * over every Logger to see which one was not enabled.
						 */
						if (event.name.equals("*")) {
							enableCmd.name = event.name;
							enableCmd.lttngLogLevel = event.logLevel.level;
							enableCmd.lttngLogLevelType = event.logLevel.type;
							/*
							 * The return value is irrelevant since the * event is
							 * always kept in the set.
							 */
							enableCmd.execute(handler, enabledLoggers);
							continue;
						}

						ret = enableCmd.enableLogger(handler, event, enabledLoggers);
						if (ret == 1) {
							/* Enabled so remove the event from the set. */
							if (!modifiedEvents.remove(event)) {
								/*
								 * event can only be present in one of
								 * the sets.
								 */
								it.remove();
							}
						}
					}
					enabledEventSet.addAll(modifiedEvents);
				}

			}
		}, this.timerDelay, this.timerDelay);

		this.timerInitialized = true;
	}

	public void init(LTTngLogHandler handler) throws InterruptedException {
		this.handler = handler;

		for (;;) {
			if (this.quit) {
				break;
			}

			try {

				/*
				 * Connect to the session daemon before anything else.
				 */
				connectToSessiond();

				/*
				 * Register to the session daemon as the Java component of the
				 * UST application.
				 */
				registerToSessiond();

				setupEventTimer();

				/*
				 * Block on socket receive and wait for command from the
				 * session daemon. This will return if and only if there is a
				 * fatal error or the socket closes.
				 */
				handleSessiondCmd();
			} catch (UnknownHostException uhe) {
				this.registerSem.release();
				System.out.println(uhe);
			} catch (IOException ioe) {
				this.registerSem.release();
				Thread.sleep(3000);
			} catch (Exception e) {
				this.registerSem.release();
				e.printStackTrace();
			}
		}
	}

	public void destroy() {
		this.quit = true;
		this.eventTimer.cancel();

		try {
			if (this.sessiondSock != null) {
				this.sessiondSock.close();
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	/*
	 * Receive header data from the session daemon using the LTTng command
	 * static buffer of the right size.
	 */
	private void recvHeader() throws Exception {
		int read_len;
		byte data[] = new byte[this.headerCmd.SIZE];

		read_len = this.inFromSessiond.read(data, 0, data.length);
		if (read_len != data.length) {
			throw new IOException();
		}
		this.headerCmd.populate(data);
	}

	/*
	 * Receive payload from the session daemon. This MUST be done after a
	 * recvHeader() so the header value of a command are known.
	 *
	 * The caller SHOULD use isPayload() before which returns true if a payload
	 * is expected after the header.
	 */
	private byte[] recvPayload() throws Exception {
		byte payload[] = new byte[(int) this.headerCmd.data_size];

		/* Failsafe check so we don't waste our time reading 0 bytes. */
		if (payload.length == 0) {
			return null;
		}

		this.inFromSessiond.read(payload, 0, payload.length);
		return payload;
	}

	/*
	 * Handle session command from the session daemon.
	 */
	private void handleSessiondCmd() throws Exception {
		int ret_code;
		byte data[] = null;

		while (true) {
			/* Get header from session daemon. */
			recvHeader();

			if (headerCmd.data_size > 0) {
				data = recvPayload();
			}

			switch (headerCmd.cmd) {
				case CMD_REG_DONE:
				{
					/*
					 * Release semaphore so meaning registration is done and we
					 * can proceed to continue tracing.
					 */
					this.registerSem.release();
					break;
				}
				case CMD_LIST:
				{
					LTTngSessiondCmd2_4.sessiond_list_logger listLoggerCmd =
						new LTTngSessiondCmd2_4.sessiond_list_logger();
					listLoggerCmd.execute(this.handler);
					data = listLoggerCmd.getBytes();
					break;
				}
				case CMD_ENABLE:
				{
					LTTngEvent event;
					LTTngSessiondCmd2_4.sessiond_enable_handler enableCmd =
						new LTTngSessiondCmd2_4.sessiond_enable_handler();
					if (data == null) {
						enableCmd.code = LTTngSessiondCmd2_4.lttng_jul_ret_code.CODE_INVALID_CMD;
						break;
					}
					enableCmd.populate(data);
					event = enableCmd.execute(this.handler, this.enabledLoggers);
					if (event != null) {
						/*
						 * Add the event to the set so it can be enabled if
						 * the logger appears at some point in time.
						 */
						enabledEventSet.add(event);
					}
					data = enableCmd.getBytes();
					break;
				}
				case CMD_DISABLE:
				{
					LTTngSessiondCmd2_4.sessiond_disable_handler disableCmd =
						new LTTngSessiondCmd2_4.sessiond_disable_handler();
					if (data == null) {
						disableCmd.code = LTTngSessiondCmd2_4.lttng_jul_ret_code.CODE_INVALID_CMD;
						break;
					}
					disableCmd.populate(data);
					disableCmd.execute(this.handler);
					data = disableCmd.getBytes();
					break;
				}
				default:
				{
					data = new byte[4];
					ByteBuffer buf = ByteBuffer.wrap(data);
					buf.order(ByteOrder.BIG_ENDIAN);
					LTTngSessiondCmd2_4.lttng_jul_ret_code code =
						LTTngSessiondCmd2_4.lttng_jul_ret_code.CODE_INVALID_CMD;
					buf.putInt(code.getCode());
					break;
				}
			}

			/* Send payload to session daemon. */
			this.outToSessiond.write(data, 0, data.length);
			this.outToSessiond.flush();
		}
	}

	private void connectToSessiond() throws Exception {
		this.sessiondSock = new Socket(this.sessiondHost, this.sessiondPort);
		this.inFromSessiond = new DataInputStream(
				sessiondSock.getInputStream());
		this.outToSessiond = new DataOutputStream(
				sessiondSock.getOutputStream());
	}

	private void registerToSessiond() throws Exception {
		byte data[] = new byte[4];
		ByteBuffer buf = ByteBuffer.wrap(data);
		String pid = ManagementFactory.getRuntimeMXBean().getName().split("@")[0];

		buf.putInt(Integer.parseInt(pid));
		this.outToSessiond.write(data, 0, data.length);
		this.outToSessiond.flush();
	}
}
