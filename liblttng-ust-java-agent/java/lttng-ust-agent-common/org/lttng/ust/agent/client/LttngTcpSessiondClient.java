/*
 * Copyright (C) 2015-2016 EfficiOS Inc., Alexandre Montplaisir <alexmonthy@efficios.com>
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
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.lang.management.ManagementFactory;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.Charset;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import org.lttng.ust.agent.utils.LttngUstAgentLogger;

/**
 * Client for agents to connect to a local session daemon, using a TCP socket.
 *
 * @author David Goulet
 */
public class LttngTcpSessiondClient implements Runnable {

	private static final String SESSION_HOST = "127.0.0.1";
	private static final String ROOT_PORT_FILE = "/var/run/lttng/agent.port";
	private static final String USER_PORT_FILE = "/.lttng/agent.port";
	private static final Charset PORT_FILE_ENCODING = Charset.forName("UTF-8");

	private static final int PROTOCOL_MAJOR_VERSION = 2;
	private static final int PROTOCOL_MINOR_VERSION = 0;

	/** Command header from the session deamon. */
	private final CountDownLatch registrationLatch = new CountDownLatch(1);

	private Socket sessiondSock;
	private volatile boolean quit = false;

	private DataInputStream inFromSessiond;
	private DataOutputStream outToSessiond;

	private final ILttngTcpClientListener logAgent;
	private final int domainValue;
	private final boolean isRoot;

	/**
	 * Constructor
	 *
	 * @param logAgent
	 *            The listener this client will operate on, typically an LTTng
	 *            agent.
	 * @param domainValue
	 *            The integer to send to the session daemon representing the
	 *            tracing domain to handle.
	 * @param isRoot
	 *            True if this client should connect to the root session daemon,
	 *            false if it should connect to the user one.
	 */
	public LttngTcpSessiondClient(ILttngTcpClientListener logAgent, int domainValue, boolean isRoot) {
		this.logAgent = logAgent;
		this.domainValue = domainValue;
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
				log("Connecting to sessiond");
				connectToSessiond();

				/*
				 * Register to the session daemon as the Java component of the
				 * UST application.
				 */
				log("Registering to sessiond");
				registerToSessiond();

				/*
				 * Block on socket receive and wait for command from the
				 * session daemon. This will return if and only if there is a
				 * fatal error or the socket closes.
				 */
				log("Waiting on sessiond commands...");
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
		log("Closing client");
		this.quit = true;

		try {
			if (this.sessiondSock != null) {
				this.sessiondSock.close();
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	private void connectToSessiond() throws IOException {
		int rootPort = getPortFromFile(ROOT_PORT_FILE);
		int userPort = getPortFromFile(getHomePath() + USER_PORT_FILE);

		/*
		 * Check for the edge case of both files existing but pointing to the
		 * same port. In this case, let the root client handle it.
		 */
		if ((rootPort != 0) && (rootPort == userPort) && (!isRoot)) {
			log("User and root config files both point to port " + rootPort +
					". Letting the root client handle it.");
			throw new IOException();
		}

		int portToUse = (isRoot ? rootPort : userPort);

		if (portToUse == 0) {
			/* No session daemon available. Stop and retry later. */
			throw new IOException();
		}

		this.sessiondSock = new Socket(SESSION_HOST, portToUse);
		this.inFromSessiond = new DataInputStream(sessiondSock.getInputStream());
		this.outToSessiond = new DataOutputStream(sessiondSock.getOutputStream());
	}

	private static String getHomePath() {
		/*
		 * The environment variable LTTNG_HOME overrides HOME if
		 * defined.
		 */
		String homePath = System.getenv("LTTNG_HOME");

		if (homePath == null) {
			homePath = System.getProperty("user.home");
		}
		return homePath;
	}

	/**
	 * Read port number from file created by the session daemon.
	 *
	 * @return port value if found else 0.
	 */
	private static int getPortFromFile(String path) throws IOException {
		BufferedReader br = null;

		try {
			br = new BufferedReader(new InputStreamReader(new FileInputStream(path), PORT_FILE_ENCODING));
			String line = br.readLine();
			if (line == null) {
				/* File exists but is empty. */
				return 0;
			}

			int port = Integer.parseInt(line, 10);
			if (port < 0 || port > 65535) {
				/* Invalid value. Ignore. */
				port = 0;
			}
			return port;

		} catch (NumberFormatException e) {
			/* File contained something that was not a number. */
			return 0;
		} catch (FileNotFoundException e) {
			/* No port available. */
			return 0;
		} finally {
			if (br != null) {
				br.close();
			}
		}
	}

	private void registerToSessiond() throws IOException {
		byte data[] = new byte[16];
		ByteBuffer buf = ByteBuffer.wrap(data);
		String pid = ManagementFactory.getRuntimeMXBean().getName().split("@")[0];

		buf.putInt(domainValue);
		buf.putInt(Integer.parseInt(pid));
		buf.putInt(PROTOCOL_MAJOR_VERSION);
		buf.putInt(PROTOCOL_MINOR_VERSION);
		this.outToSessiond.write(data, 0, data.length);
		this.outToSessiond.flush();
	}

	/**
	 * Handle session command from the session daemon.
	 */
	private void handleSessiondCmd() throws IOException {
		/* Data read from the socket */
		byte inputData[] = null;
		/* Reply data written to the socket, sent to the sessiond */
		LttngAgentResponse response;

		while (true) {
			/* Get header from session daemon. */
			SessiondCommandHeader cmdHeader = recvHeader();

			if (cmdHeader.getDataSize() > 0) {
				inputData = recvPayload(cmdHeader);
			}

			switch (cmdHeader.getCommandType()) {
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
				log("Registration done");
				continue;
			}
			case CMD_LIST:
			{
				SessiondCommand listLoggerCmd = new SessiondListLoggersCommand();
				response = listLoggerCmd.execute(logAgent);
				log("Received list loggers command");
				break;
			}
			case CMD_EVENT_ENABLE:
			{
				if (inputData == null) {
					/* Invalid command */
					response = LttngAgentResponse.FAILURE_RESPONSE;
					break;
				}
				SessiondCommand enableEventCmd = new SessiondEnableEventCommand(inputData);
				response = enableEventCmd.execute(logAgent);
				log("Received enable event command: " + enableEventCmd.toString());
				break;
			}
			case CMD_EVENT_DISABLE:
			{
				if (inputData == null) {
					/* Invalid command */
					response = LttngAgentResponse.FAILURE_RESPONSE;
					break;
				}
				SessiondCommand disableEventCmd = new SessiondDisableEventCommand(inputData);
				response = disableEventCmd.execute(logAgent);
				log("Received disable event command: " + disableEventCmd.toString());
				break;
			}
			case CMD_APP_CTX_ENABLE:
			{
				if (inputData == null) {
					/* This commands expects a payload, invalid command */
					response = LttngAgentResponse.FAILURE_RESPONSE;
					break;
				}
				SessiondCommand enableAppCtxCmd = new SessiondEnableAppContextCommand(inputData);
				response = enableAppCtxCmd.execute(logAgent);
				log("Received enable app-context command");
				break;
			}
			case CMD_APP_CTX_DISABLE:
			{
				if (inputData == null) {
					/* This commands expects a payload, invalid command */
					response = LttngAgentResponse.FAILURE_RESPONSE;
					break;
				}
				SessiondCommand disableAppCtxCmd = new SessiondDisableAppContextCommand(inputData);
				response = disableAppCtxCmd.execute(logAgent);
				log("Received disable app-context command");
				break;
			}
			default:
			{
				/* Unknown command, send empty reply */
				response = null;
				log("Received unknown command, ignoring");
				break;
			}
			}

			/* Send response to the session daemon. */
			byte[] responseData;
			if (response == null) {
				responseData = new byte[4];
				ByteBuffer buf = ByteBuffer.wrap(responseData);
				buf.order(ByteOrder.BIG_ENDIAN);
			} else {
				log("Sending response: " + response.toString());
				responseData = response.getBytes();
			}
			this.outToSessiond.write(responseData, 0, responseData.length);
			this.outToSessiond.flush();
		}
	}

	/**
	 * Receive header data from the session daemon using the LTTng command
	 * static buffer of the right size.
	 */
	private SessiondCommandHeader recvHeader() throws IOException {
		byte data[] = new byte[SessiondCommandHeader.HEADER_SIZE];

		int readLen = this.inFromSessiond.read(data, 0, data.length);
		if (readLen != data.length) {
			throw new IOException();
		}
		return new SessiondCommandHeader(data);
	}

	/**
	 * Receive payload from the session daemon. This MUST be done after a
	 * recvHeader() so the header value of a command are known.
	 *
	 * The caller SHOULD use isPayload() before which returns true if a payload
	 * is expected after the header.
	 */
	private byte[] recvPayload(SessiondCommandHeader headerCmd) throws IOException {
		byte payload[] = new byte[(int) headerCmd.getDataSize()];

		/* Failsafe check so we don't waste our time reading 0 bytes. */
		if (payload.length == 0) {
			return null;
		}

		int read = inFromSessiond.read(payload, 0, payload.length);
		if (read != payload.length) {
			throw new IOException("Unexpected number of bytes read in sessiond command payload");
		}
		return payload;
	}

	/**
	 * Wrapper for this class's logging, adds the connection's characteristics
	 * to help differentiate between multiple TCP clients.
	 */
	private void log(String message) {
		LttngUstAgentLogger.log(getClass(),
				"(root=" + isRoot + ", domain=" + domainValue + ") " + message);
	}
}
