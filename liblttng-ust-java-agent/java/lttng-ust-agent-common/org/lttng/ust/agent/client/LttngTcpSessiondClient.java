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

package org.lttng.ust.agent.client;

import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.lang.management.ManagementFactory;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import org.lttng.ust.agent.AbstractLttngAgent;

/**
 * Client for agents to connect to a local session daemon, using a TCP socket.
 *
 * @author David Goulet
 */
public class LttngTcpSessiondClient implements Runnable {

	private static final String SESSION_HOST = "127.0.0.1";
	private static final String ROOT_PORT_FILE = "/var/run/lttng/agent.port";
	private static final String USER_PORT_FILE = "/.lttng/agent.port";

	private static int protocolMajorVersion = 1;
	private static int protocolMinorVersion = 0;

	/** Command header from the session deamon. */
	private final SessiondHeaderCommand headerCmd = new SessiondHeaderCommand();
	private final CountDownLatch registrationLatch = new CountDownLatch(1);

	private Socket sessiondSock;
	private volatile boolean quit = false;

	private DataInputStream inFromSessiond;
	private DataOutputStream outToSessiond;

	private final AbstractLttngAgent<?> logAgent;
	private final boolean isRoot;


	/**
	 * Constructor
	 *
	 * @param logAgent
	 *            The logging agent this client will operate on.
	 * @param isRoot
	 *            True if this client should connect to the root session daemon,
	 *            false if it should connect to the user one.
	 */
	public LttngTcpSessiondClient(AbstractLttngAgent<?> logAgent, boolean isRoot) {
		this.logAgent = logAgent;
		this.isRoot = isRoot;
	}

	/**
	 * Wait until this client has successfully established a connection to its
	 * target session daemon.
	 *
	 * @param seconds
	 *            A timeout in seconds after which this method will return
	 *            anyway.
	 * @return True if the the client actually established the connection, false
	 *         if we returned because the timeout has elapsed or the thread was
	 *         interrupted.
	 */
	public boolean waitForConnection(int seconds) {
		try {
			return registrationLatch.await(seconds, TimeUnit.SECONDS);
		} catch (InterruptedException e) {
			return false;
		}
	}

	@Override
	public void run() {
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

				/*
				 * Block on socket receive and wait for command from the
				 * session daemon. This will return if and only if there is a
				 * fatal error or the socket closes.
				 */
				handleSessiondCmd();
			} catch (UnknownHostException uhe) {
				uhe.printStackTrace();
			} catch (IOException ioe) {
				try {
					Thread.sleep(3000);
				} catch (InterruptedException e) {
					e.printStackTrace();
				}
			}
		}
	}

	/**
	 * Dispose this client and close any socket connection it may hold.
	 */
	public void close() {
		this.quit = true;

		try {
			if (this.sessiondSock != null) {
				this.sessiondSock.close();
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	/**
	 * Receive header data from the session daemon using the LTTng command
	 * static buffer of the right size.
	 */
	private void recvHeader() throws IOException {
		byte data[] = new byte[SessiondHeaderCommand.HEADER_SIZE];

		int readLen = this.inFromSessiond.read(data, 0, data.length);
		if (readLen != data.length) {
			throw new IOException();
		}
		this.headerCmd.populate(data);
	}

	/**
	 * Receive payload from the session daemon. This MUST be done after a
	 * recvHeader() so the header value of a command are known.
	 *
	 * The caller SHOULD use isPayload() before which returns true if a payload
	 * is expected after the header.
	 */
	private byte[] recvPayload() throws IOException {
		byte payload[] = new byte[(int) this.headerCmd.getDataSize()];

		/* Failsafe check so we don't waste our time reading 0 bytes. */
		if (payload.length == 0) {
			return null;
		}

		this.inFromSessiond.read(payload, 0, payload.length);
		return payload;
	}

	/**
	 * Handle session command from the session daemon.
	 */
	private void handleSessiondCmd() throws IOException {
		byte data[] = null;

		while (true) {
			/* Get header from session daemon. */
			recvHeader();

			if (headerCmd.getDataSize() > 0) {
				data = recvPayload();
			}

			switch (headerCmd.getCommandType()) {
			case CMD_REG_DONE:
			{
				/*
				 * Countdown the registration latch, meaning registration is
				 * done and we can proceed to continue tracing.
				 */
				registrationLatch.countDown();
				/*
				 * We don't send any reply to the registration done command.
				 * This just marks the end of the initial session setup.
				 */
				continue;
			}
			case CMD_LIST:
			{
				SessiondListLoggersResponse listLoggerCmd = new SessiondListLoggersResponse();
				listLoggerCmd.execute(logAgent);
				data = listLoggerCmd.getBytes();
				break;
			}
			case CMD_ENABLE:
			{
				SessiondEnableHandler enableCmd = new SessiondEnableHandler();
				if (data == null) {
					enableCmd.code = ISessiondResponse.LttngAgentRetCode.CODE_INVALID_CMD;
					break;
				}
				enableCmd.populate(data);
				enableCmd.execute(logAgent);
				data = enableCmd.getBytes();
				break;
			}
			case CMD_DISABLE:
			{
				SessiondDisableHandler disableCmd = new SessiondDisableHandler();
				if (data == null) {
					disableCmd.setRetCode(ISessiondResponse.LttngAgentRetCode.CODE_INVALID_CMD);
					break;
				}
				disableCmd.populate(data);
				disableCmd.execute(logAgent);
				data = disableCmd.getBytes();
				break;
			}
			default:
			{
				data = new byte[4];
				ByteBuffer buf = ByteBuffer.wrap(data);
				buf.order(ByteOrder.BIG_ENDIAN);
				break;
			}
			}

			if (data == null) {
				/*
				 * Simply used to silence a potential null access warning below.
				 *
				 * The flow analysis gets confused here and thinks "data" may be
				 * null at this point. It should not happen according to program
				 * logic, if it does we've done something wrong.
				 */
				throw new IllegalStateException();
			}
			/* Send payload to session daemon. */
			this.outToSessiond.write(data, 0, data.length);
			this.outToSessiond.flush();
		}
	}

	private static String getHomePath() {
		return System.getProperty("user.home");
	}

	/**
	 * Read port number from file created by the session daemon.
	 *
	 * @return port value if found else 0.
	 */
	private static int getPortFromFile(String path) throws IOException {
		int port;
		BufferedReader br = null;

		try {
			br = new BufferedReader(new FileReader(path));
			String line = br.readLine();
			port = Integer.parseInt(line, 10);
			if (port < 0 || port > 65535) {
				/* Invalid value. Ignore. */
				port = 0;
			}
		} catch (FileNotFoundException e) {
			/* No port available. */
			port = 0;
		} finally {
			if (br != null) {
				br.close();
			}
		}

		return port;
	}

	private void connectToSessiond() throws IOException {
		int port;

		if (this.isRoot) {
			port = getPortFromFile(ROOT_PORT_FILE);
			if (port == 0) {
				/* No session daemon available. Stop and retry later. */
				throw new IOException();
			}
		} else {
			port = getPortFromFile(getHomePath() + USER_PORT_FILE);
			if (port == 0) {
				/* No session daemon available. Stop and retry later. */
				throw new IOException();
			}
		}

		this.sessiondSock = new Socket(SESSION_HOST, port);
		this.inFromSessiond = new DataInputStream(sessiondSock.getInputStream());
		this.outToSessiond = new DataOutputStream(sessiondSock.getOutputStream());
	}

	private void registerToSessiond() throws IOException {
		byte data[] = new byte[16];
		ByteBuffer buf = ByteBuffer.wrap(data);
		String pid = ManagementFactory.getRuntimeMXBean().getName().split("@")[0];

		buf.putInt(logAgent.getDomain().value());
		buf.putInt(Integer.parseInt(pid));
		buf.putInt(protocolMajorVersion);
		buf.putInt(protocolMinorVersion);
		this.outToSessiond.write(data, 0, data.length);
		this.outToSessiond.flush();
	}
}
