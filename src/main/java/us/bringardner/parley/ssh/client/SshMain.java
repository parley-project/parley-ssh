/**
 * <PRE>
 *
 * Copyright Tony Bringardner 2026 <A href="http://bringardner.com/tony">Tony Bringardner</A>
 *
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       <A href="http://www.apache.org/licenses/LICENSE-2.0">http://www.apache.org/licenses/LICENSE-2.0</A>
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 *  </PRE>
 *
 *
 *	@author Tony Bringardner
 *
 *
 * ~version~V000.00.01-V000.00.00-
 */
package us.bringardner.parley.ssh.client;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.net.ConnectException;
import java.net.NoRouteToHostException;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import us.bringardner.parley.ssh.SshException;
import us.bringardner.parley.ssh.algorithms.ISignatureAlgorithm;
import us.bringardner.parley.ssh.algorithms.NamedFactory;
import us.bringardner.parley.ssh.algorithms.SshAlgorithms;
import us.bringardner.parley.ssh.algorithms.SshCertificate;
import us.bringardner.parley.ssh.algorithms.SshPublicKeys;
import us.bringardner.parley.ssh.algorithms.ZlibCompression;
import us.bringardner.parley.ssh.keys.SshKeyLoader;
import us.bringardner.parley.ssh.transport.SshTransport;

/**
 * An ssh command: log in to a server and run a shell or a command, as OpenSSH's ssh(1) does.
 *
 * <pre>
 * java -cp ... us.bringardner.parley.ssh.client.SshMain [options] [user@]host [command]
 * </pre>
 *
 * The options are OpenSSH's (see {@link #usage()}), and ~/.ssh/config and /etc/ssh/ssh_config
 * are read for the host. Host keys are checked against ~/.ssh/known_hosts, asking about new
 * hosts. The login tries the SSH agent's keys, the identity files (asking for passphrases when
 * needed), then keyboard-interactive and password, asking on the terminal. A shell (or ssh -t)
 * gets a pseudo terminal, with the local terminal in raw mode; ~. disconnects and ~? lists the
 * other escapes. The exit status is the remote command's, or 255 if ssh itself failed.
 *
 * @author Tony Bringardner
 */
public final class SshMain {

	private static final int FAILED = 255;

	private final CliTerminal terminal;
	private final boolean manageLogging;
	private SshOptions options;
	private SshAgent agent;
	private volatile boolean disconnectRequested;
	private volatile boolean rawMode;
	private final List<PortForwarder> forwarders = new ArrayList<PortForwarder>();

	SshMain(CliTerminal terminal, boolean manageLogging) {
		this.terminal = terminal;
		this.manageLogging = manageLogging;
	}

	public static void main(String[] args) {
		int status = new SshMain(CliTerminal.system(), true).run(args);
		System.exit(status);
	}

	/**
	 * @return the exit status: the remote command's, 255 if ssh failed
	 */
	int run(String... args) {
		PrintStream err = terminal.err();
		SshOptions o;
		try {
			o = SshOptions.parse(args);
		} catch (SshOptions.UsageException e) {
			err.println("ssh: "+e.getMessage());
			err.print(usage());
			return FAILED;
		}
		if( o.help ) {
			err.print(usage());
			return 0;
		}
		if( o.showVersion ) {
			err.println(version());
			return 0;
		}
		options = o;
		try {
			readConfig(o);
		} catch (SshOptions.UsageException | IOException e) {
			err.println(e.getMessage());
			return FAILED;
		}
		o.finish();
		if( manageLogging ) {
			setLogging(o);
		}
		try {
			return connectAndRun(o);
		} finally {
			terminal.restore();
			if( agent != null ) {
				try {
					agent.close();
				} catch (IOException e) {
					// closing anyway
				}
			}
		}
	}

	// ------------------------------------------------------------------ setup

	static String usage() {
		return "usage: ssh [-AaCNnqsTtVvx] [-c cipher_spec] [-e escape_char] [-F configfile]\n"
				+"           [-i identity_file] [-L [bind_address:]port:host:hostport]\n"
				+"           [-l login_name] [-m mac_spec] [-o option] [-p port]\n"
				+"           [-R [bind_address:]port:host:hostport] [user@]hostname [command]\n";
	}

	static String version() {
		Package p = SshMain.class.getPackage();
		String v = p == null ? null : p.getImplementationVersion();
		return "Parley SSH client"+(v == null ? "" : " "+v)+" ("+SshTransport.DEFAULT_VERSION+"), Java "+System.getProperty("java.version");
	}

	private void readConfig(SshOptions o) throws IOException, SshOptions.UsageException {
		SshConfigFile reader = new SshConfigFile(o, this::debug);
		if( o.configFile != null ) {
			if( o.configFile.equalsIgnoreCase("none") ) {
				return;
			}
			File f = o.file(o.configFile);
			if( !f.isFile() ) {
				throw new SshOptions.UsageException("Can't open user config file "+f+": No such file or directory");
			}
			// A user config file: relative Include names are in ~/.ssh, as for ~/.ssh/config
			reader.read(f, dotSsh(), true);
			reader.finish();
			return;
		}
		File dotSsh = dotSsh();
		reader.read(new File(dotSsh, "config"), dotSsh, true);
		File etc = new File("/etc/ssh");
		reader.read(new File(etc, "ssh_config"), etc, false);
		reader.finish();
	}

	private static File dotSsh() {
		return new File(System.getProperty("user.home"), ".ssh");
	}

	/** The library logs (to stderr): nothing unless -v, as OpenSSH's own messages are shown instead */
	private static void setLogging(SshOptions o) {
		if( System.getProperty("logFile") == null ) {
			System.setProperty("logFile", "System.err");
		}
		if( System.getProperty("logLevel") == null ) {
			String level = "NONE";
			if( o.verbose >= 2 || o.logLevel.startsWith("DEBUG") ) {
				level = "DEBUG";
			} else if( o.verbose == 1 || o.logLevel.equals("VERBOSE") ) {
				level = "INFO";
			}
			System.setProperty("logLevel", level);
		}
	}

	private boolean isVerbose() {
		return options != null && (options.verbose > 0 || options.logLevel != null
				&& (options.logLevel.equals("VERBOSE") || options.logLevel.startsWith("DEBUG")));
	}

	private void debug(String msg) {
		if( isVerbose() ) {
			message("debug1: "+msg);
		}
	}

	/** A message on stderr, with "\r\n" while the terminal is raw */
	private void message(String msg) {
		PrintStream err = terminal.err();
		if( rawMode ) {
			err.print(msg+"\r\n");
			err.flush();
		} else {
			err.println(msg);
		}
	}

	// ------------------------------------------------------------------ connect, log in, run

	private int connectAndRun(SshOptions o) {
		PrintStream err = terminal.err();
		try (SshClient client = new SshClient()) {
			try {
				configureAlgorithms(client.getAlgorithms(), o);
			} catch (IllegalArgumentException e) {
				err.println("ssh: "+e.getMessage());
				return FAILED;
			}
			if( o.serverAliveInterval != null && o.serverAliveInterval > 0 ) {
				client.setKeepAliveInterval(o.serverAliveInterval*1000L);
			}
			// No limit by default: the host key question may take a while to answer
			client.setConnectTimeout(o.connectTimeout == null ? 0 : o.connectTimeout*1000L);
			PromptingHostKeyVerifier verifier = new PromptingHostKeyVerifier(
					PromptingHostKeyVerifier.files(o, o.userKnownHostsFiles),
					PromptingHostKeyVerifier.files(o, o.globalKnownHostsFiles),
					!Boolean.FALSE.equals(o.hashKnownHosts), o.strictHostKeyChecking, terminal, o.isBatch(), o.isQuiet());
			verifier.setAlias(o.hostKeyAlias);
			client.setHostKeyVerifier(verifier);

			debug("Connecting to "+o.hostName+" port "+o.port+".");
			ClientSession session;
			try {
				session = client.connectAndWait(o.hostName, o.port);
			} catch (IOException e) {
				if( verifier.failed() ) {
					err.println("Host key verification failed.");
				} else {
					err.println(connectError(o, e));
				}
				return FAILED;
			}
			debug("Connected, server "+session.getPeerVersion()+", host key "+SshPublicKeys.fingerprint(session.getServerHostKey()));
			if( o.serverAliveCountMax != null ) {
				session.setMaxKeepAliveFailures(o.serverAliveCountMax);
			}
			// Asking for passwords takes as long as it takes
			session.setAuthTimeout(0);
			session.setBannerListener(text -> {
				if( !o.isQuiet() ) {
					err.print(text);
					err.flush();
				}
			});

			List<IClientAuthMethod> methods = authMethods(o);
			try {
				session.authenticateAndWait(o.user, methods.toArray(new IClientAuthMethod[0]));
			} catch (IOException e) {
				err.println(o.user+"@"+o.hostName+": Permission denied ("+authProblem(e)+").");
				return FAILED;
			}
			debug("Authenticated to "+o.hostName+" as "+o.user+".");

			if( !startForwarding(session, o) ) {
				return FAILED;
			}
			if( o.noCommand ) {
				while( session.isOpen() ) {
					Thread.sleep(500);
				}
				return 0;
			}
			return runSession(session, o);
		} catch (IOException e) {
			terminal.restore();
			rawMode = false;
			err.println("ssh: "+message(e));
			return FAILED;
		} catch (InterruptedException e) {
			Thread.currentThread().interrupt();
			return FAILED;
		} finally {
			for (PortForwarder f : forwarders) {
				f.close();
			}
		}
	}

	private static String connectError(SshOptions o, Throwable e) {
		for (Throwable t = e; t != null; t = t.getCause()) {
			if( t instanceof UnknownHostException || t instanceof java.nio.channels.UnresolvedAddressException ) {
				return "ssh: Could not resolve hostname "+o.hostName+": Name or service not known";
			}
			if( t instanceof ConnectException || t instanceof NoRouteToHostException ) {
				String m = t.getMessage();
				if( m != null && m.toLowerCase().startsWith("connection refused") ) {
					m = "Connection refused";
				}
				return "ssh: connect to host "+o.hostName+" port "+o.port+": "+(m == null ? t.getClass().getSimpleName() : m);
			}
			if( t instanceof SocketTimeoutException ) {
				return "ssh: connect to host "+o.hostName+" port "+o.port+": Connection timed out";
			}
		}
		return "ssh: "+o.hostName+" port "+o.port+": "+message(e);
	}

	private static String message(Throwable e) {
		String m = e.getMessage();
		return m == null || m.isEmpty() ? e.getClass().getSimpleName() : m;
	}

	/** "Authentication of x failed; the server allows [a, b]" as OpenSSH's "a,b" */
	private static String authProblem(IOException e) {
		String m = message(e);
		int i = m.lastIndexOf("allows [");
		if( i >= 0 && m.endsWith("]") ) {
			return m.substring(i+8, m.length()-1).replace(", ", ",");
		}
		return m;
	}

	// ------------------------------------------------------------------ algorithms

	private static void configureAlgorithms(SshAlgorithms a, SshOptions o) {
		if( o.ciphers != null ) {
			a.setCiphers(edit(factoryNames(a.getCiphers()), o.ciphers));
		}
		if( o.macs != null ) {
			a.setMacs(edit(factoryNames(a.getMacs()), o.macs));
		}
		if( o.kexAlgorithms != null ) {
			a.setKeyExchanges(edit(factoryNames(a.getKeyExchanges()), o.kexAlgorithms));
		}
		if( o.hostKeyAlgorithms != null ) {
			List<String> names = new ArrayList<String>();
			for (ISignatureAlgorithm s : a.getHostKeyAlgorithms()) {
				names.add(s.getName());
			}
			a.setHostKeyAlgorithms(edit(names, o.hostKeyAlgorithms));
		}
		if( Boolean.TRUE.equals(o.compression) ) {
			a.setCompressions(ZlibCompression.ZLIB_OPENSSH, ZlibCompression.ZLIB, "none");
		} else if( Boolean.FALSE.equals(o.compression) ) {
			a.setCompressions("none");
		}
	}

	private static List<String> factoryNames(List<? extends NamedFactory<?>> list) {
		List<String> ret = new ArrayList<String>();
		for (NamedFactory<?> f : list) {
			ret.add(f.getName());
		}
		return ret;
	}

	/**
	 * An OpenSSH algorithm list: "a,b" (these), "+a,b" (add at the end), "-a,b" (remove, * and ?
	 * allowed) or "^a,b" (put first).
	 */
	static String[] edit(List<String> current, String spec) {
		List<String> ret = new ArrayList<String>(current);
		char op = spec.isEmpty() ? ' ' : spec.charAt(0);
		List<String> names = Arrays.asList((op == '+' || op == '-' || op == '^' ? spec.substring(1) : spec).split(","));
		switch (op) {
		case '+':
			for (String n : names) {
				if( !ret.contains(n) ) {
					ret.add(n);
				}
			}
			break;
		case '-':
			ret.removeIf(n -> SshConfigFile.matches(n, names));
			break;
		case '^':
			ret.removeAll(names);
			ret.addAll(0, names);
			break;
		default:
			ret = new ArrayList<String>(names);
		}
		if( ret.isEmpty() ) {
			throw new IllegalArgumentException("no algorithms left from "+spec);
		}
		return ret.toArray(new String[0]);
	}

	// ------------------------------------------------------------------ login methods

	private List<IClientAuthMethod> authMethods(SshOptions o) {
		List<IClientAuthMethod> ret = new ArrayList<IClientAuthMethod>();
		for (String name : o.preferredAuthentications) {
			switch (name.trim()) {
			case "publickey":
				if( !Boolean.FALSE.equals(o.pubkeyAuthentication) ) {
					publicKeyMethods(o, ret);
				}
				break;
			case "keyboard-interactive":
				if( !Boolean.FALSE.equals(o.kbdInteractiveAuthentication) && !o.isBatch() ) {
					for (int i = 0; i < o.numberOfPasswordPrompts; i++) {
						ret.add(PromptedAuth.keyboardInteractive(terminal));
					}
				}
				break;
			case "password":
				if( !Boolean.FALSE.equals(o.passwordAuthentication) && !o.isBatch() && o.numberOfPasswordPrompts > 0 ) {
					ret.add(new PromptedAuth.Password(terminal, o.user+"@"+o.hostName+"'s password: ", o.numberOfPasswordPrompts));
				}
				break;
			default:
				debug("Login method "+name+" is not supported");
			}
		}
		return ret;
	}

	private void publicKeyMethods(SshOptions o, List<IClientAuthMethod> ret) {
		Set<String> agentKeys = new HashSet<String>();
		if( !Boolean.TRUE.equals(o.identitiesOnly) ) {
			SshAgent a = connectAgent(o);
			if( a != null ) {
				try {
					for (SshAgent.Identity id : a.getIdentities()) {
						agentKeys.add(java.util.Base64.getEncoder().encodeToString(id.getBlob()));
					}
					if( !agentKeys.isEmpty() ) {
						ret.add(PublicKeyAuth.fromAgent(a));
						debug("Offering "+agentKeys.size()+" key(s) of the SSH agent");
					}
				} catch (IOException e) {
					debug("SSH agent: "+message(e));
				}
			}
		}
		List<KeyPair> plain = new ArrayList<KeyPair>();
		List<List<File>> plainCerts = new ArrayList<List<File>>();
		List<IClientAuthMethod> encrypted = new ArrayList<IClientAuthMethod>();
		for (String path : o.identityFiles) {
			File f = o.file(path);
			if( !f.isFile() ) {
				if( !o.defaultIdentities ) {
					message("Warning: Identity file "+f+" not accessible: No such file or directory.");
				}
				continue;
			}
			List<File> certs = new ArrayList<File>();
			File own = new File(f.getPath()+"-cert.pub");
			if( own.isFile() ) {
				certs.add(own);
			}
			for (String c : o.certificateFiles) {
				File cf = o.file(c);
				if( cf.isFile() && !certs.contains(cf) ) {
					certs.add(cf);
				}
			}
			try {
				String text = new String(Files.readAllBytes(f.toPath()), StandardCharsets.UTF_8);
				PublicKey pub = null;
				File pubFile = new File(f.getPath()+".pub");
				if( pubFile.isFile() ) {
					try {
						pub = SshKeyLoader.loadPublic(pubFile);
					} catch (IOException e) {
						debug("Can't read "+pubFile+": "+message(e));
					}
				}
				if( pub != null && agentKeys.contains(blob(pub)) && certs.isEmpty() ) {
					debug("Key "+f+" is in the agent");
					continue;
				}
				if( SshKeyLoader.isEncrypted(text) ) {
					if( !o.isBatch() ) {
						encrypted.add(new PromptedAuth.EncryptedKey(terminal, f, text, pub, certs));
					}
					continue;
				}
				KeyPair kp = SshKeyLoader.parse(text, null);
				if( agentKeys.contains(blob(kp.getPublic())) && certs.isEmpty() ) {
					debug("Key "+f+" is in the agent");
					continue;
				}
				plain.add(kp);
				plainCerts.add(certs);
				debug("Will offer "+f);
			} catch (IOException e) {
				message("Load key \""+f+"\": "+message(e));
			}
		}
		if( !plain.isEmpty() ) {
			PublicKeyAuth auth = new PublicKeyAuth(plain);
			for (int i = 0; i < plain.size(); i++) {
				for (File c : plainCerts.get(i)) {
					try {
						auth.addCertificate(plain.get(i), SshCertificate.load(c));
					} catch (IOException | IllegalArgumentException e) {
						debug("Certificate "+c+" not used: "+message(e));
					}
				}
			}
			ret.add(auth);
		}
		ret.addAll(encrypted);
	}

	private static String blob(PublicKey key) {
		return java.util.Base64.getEncoder().encodeToString(SshPublicKeys.encode(key));
	}

	private SshAgent connectAgent(SshOptions o) {
		String ia = o.identityAgent;
		if( ia != null && ia.equalsIgnoreCase("none") ) {
			return null;
		}
		try {
			if( ia == null || ia.equals("SSH_AUTH_SOCK") ) {
				if( !SshAgent.isAvailable() ) {
					return null;
				}
				agent = SshAgent.connect();
			} else if( ia.startsWith("$") ) {
				String path = System.getenv(ia.substring(1));
				if( path == null || path.isEmpty() ) {
					return null;
				}
				agent = SshAgent.connect(path);
			} else {
				agent = SshAgent.connect(o.expand(ia));
			}
			return agent;
		} catch (IOException | RuntimeException e) {
			debug("No SSH agent: "+message(e));
			return null;
		}
	}

	// ------------------------------------------------------------------ port forwarding

	private boolean startForwarding(ClientSession session, SshOptions o) {
		boolean exitOnFailure = Boolean.TRUE.equals(o.exitOnForwardFailure);
		for (SshOptions.Forward f : o.localForwards) {
			String bind = f.bindHost == null ? "localhost" : f.bindHost;
			try {
				PortForwarder p = session.startLocalForwarding(bind, f.bindPort, f.host, f.port);
				forwarders.add(p);
				debug("Local forwarding listening on "+bind+" port "+p.getBoundPort()+" to "+f.host+":"+f.port);
			} catch (IOException e) {
				message("bind ["+bind+"]:"+f.bindPort+": "+message(e));
				message("Could not request local forwarding.");
				if( exitOnFailure ) {
					return false;
				}
			}
		}
		for (SshOptions.Forward f : o.remoteForwards) {
			String bind = f.bindHost == null ? "localhost" : f.bindHost;
			try {
				PortForwarder p = session.startRemoteForwarding(bind, f.bindPort, f.host, f.port);
				forwarders.add(p);
				if( f.bindPort == 0 ) {
					message("Allocated port "+p.getBoundPort()+" for remote forward to "+f.host+":"+f.port);
				}
				debug("Remote forwarding of port "+p.getBoundPort()+" to "+f.host+":"+f.port);
			} catch (IOException e) {
				message("Warning: remote port forwarding failed for listen port "+f.bindPort);
				if( exitOnFailure ) {
					return false;
				}
			}
		}
		return true;
	}

	// ------------------------------------------------------------------ the session channel

	private int runSession(ClientSession session, SshOptions o) throws IOException, InterruptedException {
		boolean stdinTerminal = !o.stdinNull && terminal.stdinIsTerminal();
		boolean pty;
		switch (o.requestTty) {
		case "no":
			pty = false;
			break;
		case "force":
			pty = true;
			break;
		case "yes":
			pty = stdinTerminal;
			if( !pty ) {
				message("Pseudo-terminal will not be allocated because stdin is not a terminal.");
			}
			break;
		default:
			pty = o.command == null && stdinTerminal;
		}

		SessionChannel ch = session.openSession();
		String fa = o.forwardAgent;
		if( fa != null && !fa.equalsIgnoreCase("no") ) {
			session.setAgentForwarding(fa.equalsIgnoreCase("yes") ? "" : o.expand(fa));
			if( !ch.requestAgentForwarding() ) {
				debug("The server refused agent forwarding");
			}
		}
		sendEnvironment(ch, o);
		if( pty ) {
			int[] size = terminal.size();
			if( size == null ) {
				size = new int[] {80, 24};
			}
			String term = System.getenv("TERM");
			try {
				ch.requestPty(term == null || term.isEmpty() ? "vt100" : term, size[0], size[1]);
			} catch (SshException e) {
				message("PTY allocation request failed on channel "+ch.getLocalId());
				pty = false;
			}
		}
		try {
			if( o.subsystem ) {
				ch.subsystem(o.command);
			} else if( o.command != null ) {
				ch.exec(o.command);
			} else {
				ch.shell();
			}
		} catch (SshException e) {
			if( o.subsystem ) {
				message("Request for subsystem '"+o.command+"' failed on channel "+ch.getLocalId());
			} else {
				message((o.command != null ? "exec" : "shell")+" request failed on channel "+ch.getLocalId());
			}
			ch.close();
			return FAILED;
		}

		if( pty && stdinTerminal ) {
			rawMode = terminal.enterRawMode();
			terminal.onResize(() -> {
				int[] z = terminal.size();
				if( z != null && ch.isOpen() ) {
					try {
						ch.windowChange(z[0], z[1], 0, 0);
					} catch (IOException e) {
						// the session is ending
					}
				}
			});
		}

		if( o.command == null && !pty && !stdinTerminal && !o.stdinNull && !o.isQuiet() ) {
			// e.g. started from an IDE: the shell works, but would look as if nothing happened
			message("Logged in to "+o.hostName+". stdin is not a terminal, so the remote shell shows no prompt:"
					+" type commands, and exit (or end of input) to leave.");
		}
		Thread out = pump(ch.getInputStream(), terminal.out(), "ssh-stdout");
		Thread errOut = pump(ch.getErrorStream(), terminal.err(), "ssh-stderr");
		if( o.stdinNull ) {
			ch.sendEof();
		} else {
			int escape = pty ? o.escapeCharacter() : -1;
			Thread in = new Thread(() -> copyStdin(ch, escape, o), "ssh-stdin");
			in.setDaemon(true);
			in.start();
		}

		while( !ch.waitForClose(1, TimeUnit.SECONDS) ) {
			if( !session.isOpen() || disconnectRequested ) {
				break;
			}
		}
		out.join(5000);
		errOut.join(5000);
		terminal.restore();
		rawMode = false;

		if( disconnectRequested ) {
			if( !o.isQuiet() ) {
				message("Connection to "+o.hostName+" closed.");
			}
			return FAILED;
		}
		Integer status = ch.getExitStatus();
		if( status == null && !session.isOpen() && ch.getExitSignal() == null ) {
			message("Connection to "+o.hostName+" closed by remote host.");
			return FAILED;
		}
		if( pty && !o.isQuiet() ) {
			message("Connection to "+o.hostName+" closed.");
		}
		if( status != null ) {
			return status & 0xff;
		}
		if( ch.getExitSignal() != null ) {
			debug("Remote command killed by signal "+ch.getExitSignal());
		}
		return FAILED;
	}

	private void sendEnvironment(SessionChannel ch, SshOptions o) throws IOException {
		if( !o.sendEnv.isEmpty() ) {
			for (Map.Entry<String, String> e : System.getenv().entrySet()) {
				if( SshConfigFile.matches(e.getKey(), o.sendEnv) && !o.setEnv.containsKey(e.getKey()) ) {
					if( !ch.setEnv(e.getKey(), e.getValue()) ) {
						debug("The server refused environment variable "+e.getKey());
					}
				}
			}
		}
		for (Map.Entry<String, String> e : o.setEnv.entrySet()) {
			if( !ch.setEnv(e.getKey(), e.getValue()) ) {
				debug("The server refused environment variable "+e.getKey());
			}
		}
	}

	private static Thread pump(InputStream from, OutputStream to, String name) {
		Thread t = new Thread(() -> {
			byte[] buf = new byte[32*1024];
			try {
				int n;
				while( (n = from.read(buf)) >= 0 ) {
					if( n > 0 ) {
						to.write(buf, 0, n);
						to.flush();
					}
				}
			} catch (IOException e) {
				// the channel closed
			}
		}, name);
		t.setDaemon(true);
		t.start();
		return t;
	}

	/**
	 * Send stdin to the remote program, then EOF. With an escape character, a line starting
	 * with it is a command for ssh (OpenSSH's escapes): ~. disconnect, ~? help, ~# forwardings,
	 * ~~ the character itself.
	 */
	private void copyStdin(SessionChannel ch, int escape, SshOptions o) {
		InputStream in = terminal.in();
		OutputStream to = ch.getOutputStream();
		byte[] buf = new byte[8192];
		boolean lineStart = true;
		boolean afterEscape = false;
		try {
			int n;
			while( (n = in.read(buf)) >= 0 ) {
				if( escape < 0 ) {
					to.write(buf, 0, n);
					to.flush();
					continue;
				}
				ByteArrayOutputStream send = new ByteArrayOutputStream(n+1);
				for (int i = 0; i < n; i++) {
					int b = buf[i] & 0xff;
					if( afterEscape ) {
						afterEscape = false;
						if( b == '.' ) {
							to.write(send.toByteArray());
							to.flush();
							disconnectRequested = true;
							message("");
							ch.close();
							return;
						} else if( b == '?' ) {
							escapeHelp(escape);
							lineStart = true;
							continue;
						} else if( b == '#' ) {
							listForwards(o);
							lineStart = true;
							continue;
						} else if( b != escape ) {
							send.write(escape);
						}
						send.write(b);
					} else if( lineStart && b == escape ) {
						afterEscape = true;
						continue;
					} else {
						send.write(b);
					}
					lineStart = b == '\r' || b == '\n';
				}
				if( send.size() > 0 ) {
					send.writeTo(to);
					to.flush();
				}
			}
			ch.sendEof();
		} catch (IOException e) {
			// the channel closed
		}
	}

	private void escapeHelp(int escape) {
		String e = escape < ' ' ? "^"+(char) (escape+'@') : String.valueOf((char) escape);
		message("Supported escape sequences:");
		message(" "+e+".   - terminate connection");
		message(" "+e+"#   - list forwarded connections");
		message(" "+e+"?   - this message");
		message(" "+e+e+"   - send the escape character by typing it twice");
		message("(Note that escapes are only recognized immediately after newline.)");
	}

	private void listForwards(SshOptions o) {
		message("The following forwardings are set up:");
		for (SshOptions.Forward f : o.localForwards) {
			message("  local "+f);
		}
		for (SshOptions.Forward f : o.remoteForwards) {
			message("  remote "+f);
		}
	}

	// for tests
	SshOptions getOptions() {
		return options;
	}
}
