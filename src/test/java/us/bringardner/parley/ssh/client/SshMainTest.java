package us.bringardner.parley.ssh.client;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.io.PrintStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Deque;
import java.util.List;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import us.bringardner.parley.ssh.algorithms.SshPublicKeys;
import us.bringardner.parley.ssh.keys.SshKeyWriter;
import us.bringardner.parley.ssh.server.AbstractCommand;
import us.bringardner.parley.ssh.server.AuthorizedKeysAuthenticator;
import us.bringardner.parley.ssh.server.CommandEnvironment;
import us.bringardner.parley.ssh.server.ForwardingFilters;
import us.bringardner.parley.ssh.server.HostKeyProviders;
import us.bringardner.parley.ssh.server.ICommand;
import us.bringardner.parley.ssh.server.SshPrincipal;
import us.bringardner.parley.ssh.server.SshServer;

/**
 * The ssh command (SshMain): its command line and config files, then whole runs against an
 * in-process SshServer with a stand-in terminal.
 */
public class SshMainTest {

	@TempDir
	File dir;

	private SshServer server;

	@AfterEach
	public void stop() throws Exception {
		if( server != null ) {
			server.stop(5000, false);
		}
	}

	// ------------------------------------------------------------------ the command line

	@Test
	public void commandLine() throws Exception {
		SshOptions o = SshOptions.parse("-vvAt", "-p2222", "-l", "bob", "-o", "Compression=yes", "-i", "k1", "-ik2",
				"alice@example.com", "ls", "-l", "/tmp");
		assertEquals(2, o.verbose);
		assertEquals("yes", o.forwardAgent);
		assertEquals("yes", o.requestTty);
		assertEquals(Integer.valueOf(2222), o.port);
		assertEquals("bob", o.user, "-l comes before user@ (the first value wins)");
		assertEquals(Boolean.TRUE, o.compression);
		assertEquals(Arrays.asList("k1", "k2"), o.identityFiles);
		assertEquals("example.com", o.host);
		assertEquals("ls -l /tmp", o.command);

		o = SshOptions.parse("-tt", "-o", "User carol", "-o", "Port = 2200", "host");
		assertEquals("force", o.requestTty);
		assertEquals("carol", o.user);
		assertEquals(Integer.valueOf(2200), o.port);
		assertNull(o.command);
		o.finish();
		assertEquals("host", o.hostName);
		assertEquals("ask", o.strictHostKeyChecking);
		assertTrue(o.defaultIdentities);

		o = SshOptions.parse("-T", "-t", "-e", "^]", "-s", "h", "sftp");
		assertEquals("no", o.requestTty, "-T before -t wins");
		assertEquals(0x1d, finish(o).escapeCharacter());
		assertTrue(o.subsystem);

		assertEquals(-1, finish(SshOptions.parse("-e", "none", "h")).escapeCharacter());
		assertEquals('%', finish(SshOptions.parse("-e", "%", "h")).escapeCharacter());
		// As OpenSSH, options may follow the host; the command starts at the first other word (or --)
		o = SshOptions.parse("host", "-p", "2201", "-v", "ls", "-l");
		assertEquals(Integer.valueOf(2201), o.port);
		assertEquals(1, o.verbose);
		assertEquals("ls -l", o.command);
		o = SshOptions.parse("host", "--", "-x", "y");
		assertEquals("-x y", o.command);
		o = SshOptions.parse("--", "host", "cmd");
		assertEquals("host", o.host);
		assertEquals("cmd", o.command);
		// Keywords for features this client doesn't have are accepted, as in config files
		SshOptions.parse("-o", "CheckHostIP=no", "-o", "ControlMaster auto", "host");

		assertTrue(SshOptions.parse("-V").showVersion);
		assertTrue(SshOptions.parse("--help").help);
	}

	private static SshOptions finish(SshOptions o) {
		o.finish();
		return o;
	}

	@Test
	public void badCommandLines() {
		assertThrows(SshOptions.UsageException.class, () -> SshOptions.parse());
		assertThrows(SshOptions.UsageException.class, () -> SshOptions.parse("-v"));
		assertThrows(SshOptions.UsageException.class, () -> SshOptions.parse("-Z", "host"));
		assertThrows(SshOptions.UsageException.class, () -> SshOptions.parse("-D", "1080", "host"), "dynamic forwarding isn't supported");
		assertThrows(SshOptions.UsageException.class, () -> SshOptions.parse("host", "-p"), "options go on after the host");
		assertDoesNotThrow(() -> SshOptions.parse("host", "cmd", "-p"), "the command's");
		assertThrows(SshOptions.UsageException.class, () -> SshOptions.parse("-p"));
		assertThrows(SshOptions.UsageException.class, () -> SshOptions.parse("-p", "70000", "host"));
		assertThrows(SshOptions.UsageException.class, () -> SshOptions.parse("-o", "NoSuchOption yes", "host"));
		assertThrows(SshOptions.UsageException.class, () -> SshOptions.parse("-o", "StrictHostKeyChecking maybe", "host"));
		assertThrows(SshOptions.UsageException.class, () -> SshOptions.parse("-L", "8080", "host"));
		assertThrows(SshOptions.UsageException.class, () -> SshOptions.parse("-s", "host"));
	}

	@Test
	public void forwardSpecs() throws Exception {
		SshOptions.Forward f = SshOptions.parseForward("8080:intranet:80");
		assertNull(f.bindHost);
		assertEquals(8080, f.bindPort);
		assertEquals("intranet", f.host);
		assertEquals(80, f.port);
		f = SshOptions.parseForward("[::1]:8080:[fe80::1]:80");
		assertEquals("::1", f.bindHost);
		assertEquals("fe80::1", f.host);
		f = SshOptions.parseForward("*:0:localhost:22");
		assertEquals("0.0.0.0", f.bindHost);
		assertEquals(0, f.bindPort);
		assertThrows(SshOptions.UsageException.class, () -> SshOptions.parseForward("a:b:c:d"));
		assertThrows(SshOptions.UsageException.class, () -> SshOptions.parseForward("80:host"));
		assertThrows(SshOptions.UsageException.class, () -> SshOptions.parseForward("80:host:0"));
	}

	@Test
	public void tokenize() {
		assertEquals(Arrays.asList("Host", "a", "b"), SshOptions.tokenize("Host a b"));
		assertEquals(Arrays.asList("Port", "22"), SshOptions.tokenize("Port=22"));
		assertEquals(Arrays.asList("Port", "22"), SshOptions.tokenize("  Port = 22 "));
		assertEquals(Arrays.asList("IdentityFile", "/a b/c"), SshOptions.tokenize("IdentityFile \"/a b/c\""));
		assertEquals(Arrays.asList("SetEnv", "A=1", "B=x=y"), SshOptions.tokenize("SetEnv A=1 B=x=y"));
	}

	// ------------------------------------------------------------------ config files

	@Test
	public void configFiles() throws Exception {
		File inc = new File(dir, "conf.d");
		inc.mkdirs();
		write(new File(inc, "10-work.conf"), "Host *.work\n  User worker\n  Port 2201\n");
		write(new File(inc, "README"), "Port 1\n");
		File cfg = write(new File(dir, "config"),
				"# a comment\n"
				+"Include conf.d/*.conf\n"
				+"Host db.work\n"
				+"  HostName 10.0.0.5\n"
				+"  IdentityFile ~/.ssh/db_%r_%h\n"
				+"  LocalForward 5432 localhost:5432\n"
				+"Host * !*.home\n"
				+"  User everyone\n"
				+"  ServerAliveInterval 15\n"
				+"  SendEnv LANG LC_*\n"
				+"  NoSuchKeyword whatever\n"
				+"Match host 10.0.0.*\n"
				+"  Compression yes\n"
				+"Match exec \"true\"\n"
				+"  Port 9\n"
				+"Host *\n"
				+"  Port 2299\n"
				+"  IdentityFile ~/.ssh/other\n");
		List<String> ignored = new ArrayList<String>();
		SshOptions o = SshOptions.parse("-p", "2200", "db.work");
		new SshConfigFile(o, ignored::add).read(cfg, dir, true);
		o.finish();
		assertEquals("10.0.0.5", o.hostName);
		assertEquals("worker", o.user, "the included file comes first");
		assertEquals(Integer.valueOf(2200), o.port, "the command line wins");
		assertEquals(Integer.valueOf(15), o.serverAliveInterval);
		assertEquals(Boolean.TRUE, o.compression, "Match host is the HostName");
		assertEquals(Arrays.asList("~/.ssh/db_%r_%h", "~/.ssh/other"), o.identityFiles, "lists collect every value");
		assertEquals(System.getProperty("user.home")+"/.ssh/db_worker_10.0.0.5", o.expand(o.identityFiles.get(0)));
		assertEquals(Arrays.asList("LANG", "LC_*"), o.sendEnv);
		assertEquals(1, o.localForwards.size());
		assertEquals(5432, o.localForwards.get(0).bindPort);
		assertTrue(ignored.stream().anyMatch(s -> s.contains("NoSuchKeyword")), ignored.toString());
		assertTrue(ignored.stream().anyMatch(s -> s.contains("Match exec")), ignored.toString());

		o = SshOptions.parse("pc.home");
		new SshConfigFile(o, s -> { }).read(cfg, dir, true);
		o.finish();
		assertEquals(System.getProperty("user.name"), o.user, "!*.home excludes the block");
		assertEquals(Integer.valueOf(2299), o.port);
		assertEquals(Boolean.TRUE.equals(o.compression), false);

		write(cfg, "Port abc\n");
		SshOptions bad = SshOptions.parse("h");
		assertThrows(SshOptions.UsageException.class, () -> new SshConfigFile(bad, s -> { }).read(cfg, dir, true));
		// The system's file: reported, not fatal
		new SshConfigFile(bad, s -> { }).read(cfg, dir, false);
	}

	@Test
	public void matchFinalAndIncludeWildcards() throws Exception {
		File a = new File(dir, "hosts/a");
		File b = new File(dir, "hosts/b");
		a.mkdirs();
		b.mkdirs();
		write(new File(a, "config"), "Host x\n  User from-a\n");
		write(new File(b, "config"), "Host x\n  User from-b\n  Port 2001\n");
		File cfg = write(new File(dir, "config"),
				"Match final host x\n"
				+"  Port 2002\n"
				+"  Compression yes\n"
				+"Include "+dir+"/hosts/*/config\n");
		SshOptions o = SshOptions.parse("x");
		SshConfigFile r = new SshConfigFile(o, s -> { });
		r.read(cfg, dir, true);
		r.finish();
		o.finish();
		assertEquals("from-a", o.user, "wildcards in a directory name: in order");
		assertEquals(Integer.valueOf(2001), o.port, "values from the first pass win over Match final's");
		assertEquals(Boolean.TRUE, o.compression, "Match final fills in what is still unset");
	}

	@Test
	public void globs() {
		assertTrue(SshConfigFile.glob("*.example.com", "a.b.EXAMPLE.com"));
		assertTrue(SshConfigFile.glob("host?", "host1"));
		assertFalse(SshConfigFile.glob("host?", "host12"));
		assertTrue(SshConfigFile.matches("x", Arrays.asList("a,x")));
		assertFalse(SshConfigFile.matches("x", Arrays.asList("*", "!x")));
	}

	@Test
	public void algorithmLists() {
		List<String> cur = Arrays.asList("a", "b", "c");
		assertArrayEquals(new String[] {"x", "y"}, SshMain.edit(cur, "x,y"));
		assertArrayEquals(new String[] {"a", "b", "c", "d"}, SshMain.edit(cur, "+d,a"));
		assertArrayEquals(new String[] {"a"}, SshMain.edit(cur, "-b,c"));
		assertArrayEquals(new String[] {"c"}, SshMain.edit(cur, "-[ab]*,a*,b"));
		assertArrayEquals(new String[] {"c", "a", "b"}, SshMain.edit(cur, "^c"));
		assertThrows(IllegalArgumentException.class, () -> SshMain.edit(cur, "-*"));
	}

	// ------------------------------------------------------------------ runs

	/** Commands: echo, fail N (stderr, status N), cat, env NAME, whoami */
	private static ICommand command(String line) {
		String[] w = line.split(" ", 2);
		String arg = w.length > 1 ? w[1] : "";
		return new AbstractCommand() {
			@Override
			protected int run(CommandEnvironment env, InputStream in, OutputStream out, OutputStream err) throws Exception {
				switch (w[0]) {
				case "echo":
					out.write((arg+"\n").getBytes(StandardCharsets.UTF_8));
					return 0;
				case "fail":
					err.write("failing\n".getBytes(StandardCharsets.UTF_8));
					return Integer.parseInt(arg);
				case "cat":
					in.transferTo(out);
					return 0;
				case "env":
					out.write(String.valueOf(env.getEnv().get(arg)).getBytes(StandardCharsets.UTF_8));
					return 0;
				case "whoami":
					out.write(env.getUser().getBytes(StandardCharsets.UTF_8));
					return 0;
				default:
					return 127;
				}
			}
		};
	}

	/** A shell that answers each line with "TERM COLSxROWS> line" until "exit" */
	private static ICommand shell() {
		return new AbstractCommand() {
			@Override
			protected int run(CommandEnvironment env, InputStream in, OutputStream out, OutputStream err) throws Exception {
				BufferedReader r = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8));
				PrintStream p = new PrintStream(out, true, "UTF-8");
				p.print("ready\r\n");
				String line;
				while( (line = r.readLine()) != null ) {
					if( line.equals("exit") ) {
						return 4;
					}
					p.print(env.getTerm()+" "+env.getColumns()+"x"+env.getRows()+"> "+line+"\r\n");
				}
				return 1;
			}
		};
	}

	private KeyPair alicesKey;

	private SshServer start() throws Exception {
		KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
		g.initialize(new ECGenParameterSpec("secp256r1"));
		alicesKey = g.generateKeyPair();
		SshServer s = new SshServer(0);
		s.setName("ssh-main-test");
		s.setHostKeyProvider(HostKeyProviders.ephemeral());
		s.setPasswordAuthenticator((user, pw, ctx) -> "alice".equals(user) && "secret".equals(new String(pw)) ? new SshPrincipal(user) : null);
		File keys = new File(dir, "authorized_keys");
		write(keys, SshPublicKeys.toOpenSsh(alicesKey.getPublic())+" alice@test\n");
		s.setPublicKeyAuthenticator(new AuthorizedKeysAuthenticator(user -> "alice".equals(user) ? keys : null));
		s.setCommandFactory((line, env) -> command(line));
		s.setShellFactory(env -> shell());
		s.setForwardingFilter(ForwardingFilters.allowAll());
		s.setLoginFailureDelay(10);
		s.startAndWait(5000);
		server = s;
		return s;
	}

	private File knownHosts() {
		return new File(dir, "known_hosts");
	}

	/** The options every run gets: this server, no config files, no agent, no default keys, known_hosts in dir */
	private List<String> args(String... more) {
		List<String> a = new ArrayList<String>(Arrays.asList("-F", "none", "-p", String.valueOf(server.getLocalPort()),
				"-o", "UserKnownHostsFile "+knownHosts(), "-o", "GlobalKnownHostsFile none",
				"-o", "IdentityAgent none", "-o", "IdentitiesOnly yes"));
		a.addAll(Arrays.asList(more));
		return a;
	}

	private int run(TestTerminal t, List<String> args) {
		return new SshMain(t, false).run(args.toArray(new String[0]));
	}

	@Test
	public void passwordLoginAndNewHost() throws Exception {
		start();
		TestTerminal t = new TestTerminal("", "yes", "wrong", "secret");
		// (The server offers keyboard-interactive too, which is tried before password)
		assertEquals(0, run(t, args("-o", "PreferredAuthentications=publickey,password", "alice@localhost", "echo", "hi", "there")), t.stderr());
		assertEquals("hi there\n", t.stdout());
		assertEquals(3, t.prompts.size(), t.prompts.toString());
		assertTrue(t.prompts.get(0).startsWith("Are you sure you want to continue connecting"), t.prompts.toString());
		assertEquals("alice@localhost's password: ", t.prompts.get(1));
		assertTrue(t.stderr().contains("Permanently added '[localhost]:"), t.stderr());
		assertTrue(t.stderr().contains("Permission denied, please try again."), t.stderr());
		String kh = new String(Files.readAllBytes(knownHosts().toPath()), StandardCharsets.UTF_8);
		assertTrue(kh.startsWith("|1|"), "hashed: "+kh);

		// Known now: no question
		t = new TestTerminal("", "secret");
		assertEquals(0, run(t, args("-l", "alice", "localhost", "whoami")), t.stderr());
		assertEquals("alice", t.stdout());
		assertEquals(1, t.prompts.size(), t.prompts.toString());
		assertFalse(t.stderr().contains("Permanently"), t.stderr());
	}

	@Test
	public void stdinStderrAndStatus() throws Exception {
		start();
		TestTerminal t = new TestTerminal("line 1\nline 2\n", "secret");
		assertEquals(0, run(t, args("-o", "StrictHostKeyChecking accept-new", "alice@localhost", "cat")), t.stderr());
		assertEquals("line 1\nline 2\n", t.stdout());
		assertTrue(t.prompts.size() == 1, "no host key question with accept-new");

		t = new TestTerminal("", "secret");
		assertEquals(3, run(t, args("alice@localhost", "fail 3")), t.stderr());
		assertEquals("", t.stdout());
		assertTrue(t.stderr().contains("failing"), t.stderr());

		t = new TestTerminal("", "secret");
		assertEquals(127, run(t, args("alice@localhost", "nosuchcommand")), t.stderr());

		// -n: stdin isn't read (cat ends at once)
		t = new TestTerminal("not sent\n", "secret");
		assertEquals(0, run(t, args("-n", "alice@localhost", "cat")), t.stderr());
		assertEquals("", t.stdout());

		// SetEnv is sent with the command
		t = new TestTerminal("", "secret");
		assertEquals(0, run(t, args("-o", "SetEnv GREETING=hello", "alice@localhost", "env GREETING")), t.stderr());
		assertEquals("hello", t.stdout());
	}

	@Test
	public void hostKeyChecks() throws Exception {
		start();
		// Strict: an unknown host is refused before any login
		TestTerminal t = new TestTerminal("", "secret");
		assertEquals(255, run(t, args("-o", "StrictHostKeyChecking=yes", "alice@localhost", "whoami")));
		assertTrue(t.stderr().contains("you have requested strict checking"), t.stderr());
		assertTrue(t.stderr().contains("Host key verification failed."), t.stderr());
		assertTrue(t.prompts.isEmpty());

		// "no" at the question
		t = new TestTerminal("", "no");
		assertEquals(255, run(t, args("alice@localhost", "whoami")));
		assertFalse(knownHosts().exists());

		// No one to ask
		t = new TestTerminal("");
		assertEquals(255, run(t, args("alice@localhost", "whoami")));
		assertTrue(t.stderr().contains("Host key verification failed."), t.stderr());

		// Another key for the host: refused, whatever StrictHostKeyChecking says
		KnownHosts kh = new KnownHosts(knownHosts());
		for (KeyPair hk : server.getHostKeys()) {
			kh.add("localhost", server.getLocalPort(), otherKey(hk.getPublic()));
		}
		t = new TestTerminal("", "secret");
		assertEquals(255, run(t, args("-o", "StrictHostKeyChecking=no", "alice@localhost", "whoami")));
		assertTrue(t.stderr().contains("REMOTE HOST IDENTIFICATION HAS CHANGED"), t.stderr());
		assertTrue(t.prompts.isEmpty());
	}

	/** A new key of the same type */
	private static java.security.PublicKey otherKey(java.security.PublicKey key) throws Exception {
		String alg = key.getAlgorithm();
		KeyPairGenerator gen = KeyPairGenerator.getInstance(alg);
		if( key instanceof java.security.interfaces.ECPublicKey ) {
			gen.initialize(((java.security.interfaces.ECPublicKey) key).getParams());
		} else if( alg.equals("RSA") ) {
			gen.initialize(2048);
		}
		return gen.generateKeyPair().getPublic();
	}

	@Test
	public void knownInAnyFile() throws Exception {
		start();
		// The user's file has the key; a global file still has an old one: trusted (as OpenSSH)
		File global = new File(dir, "global_known_hosts");
		KnownHosts old = new KnownHosts(global);
		KnownHosts current = new KnownHosts(knownHosts());
		for (KeyPair hk : server.getHostKeys()) {
			old.add("localhost", server.getLocalPort(), otherKey(hk.getPublic()));
			current.add("localhost", server.getLocalPort(), hk.getPublic());
		}
		List<String> a = args("-o", "StrictHostKeyChecking=yes", "alice@localhost", "whoami");
		a.set(a.indexOf("GlobalKnownHostsFile none"), "GlobalKnownHostsFile "+global);
		TestTerminal t = new TestTerminal("", "secret");
		assertEquals(0, run(t, a), t.stderr());
		assertEquals("alice", t.stdout());
	}

	@Test
	public void keyboardInteractiveAndBatchMode() throws Exception {
		start();
		TestTerminal t = new TestTerminal("", "secret");
		assertEquals(0, run(t, args("-o", "StrictHostKeyChecking=accept-new", "-o", "PreferredAuthentications=keyboard-interactive",
				"alice@localhost", "whoami")), t.stderr());
		assertEquals("alice", t.stdout());
		assertEquals(1, t.prompts.size());
		assertFalse(t.prompts.get(0).contains("alice@localhost's password"), "the server's prompt: "+t.prompts);

		// BatchMode: nothing is asked, so no login
		t = new TestTerminal("", "secret");
		assertEquals(255, run(t, args("-o", "BatchMode=yes", "alice@localhost", "whoami")));
		assertTrue(t.prompts.isEmpty(), t.prompts.toString());
		assertTrue(t.stderr().contains("alice@localhost: Permission denied ("), t.stderr());
	}

	@Test
	public void keyFiles() throws Exception {
		start();
		File key = new File(dir, "id_ecdsa");
		SshKeyWriter.write(alicesKey, key, "alice@test");
		TestTerminal t = new TestTerminal("");
		assertEquals(0, run(t, args("-o", "StrictHostKeyChecking=accept-new", "-i", key.getPath(), "alice@localhost", "whoami")), t.stderr());
		assertEquals("alice", t.stdout());
		assertTrue(t.prompts.isEmpty(), t.prompts.toString());

		t = new TestTerminal("", "secret");
		assertEquals(0, run(t, args("-i", new File(dir, "missing").getPath(), "alice@localhost", "whoami")), t.stderr());
		assertTrue(t.stderr().contains("Warning: Identity file"), t.stderr());
	}

	@Test
	public void encryptedKeyFiles() throws Exception {
		File known = new File(dir, "id_known");
		File stranger = new File(dir, "id_stranger");
		assumeTrue(keygen(known, "pass phrase") && keygen(stranger, "other"), "no ssh-keygen");
		start();
		// Alice may use the first key too
		File keys = new File(dir, "authorized_keys");
		Files.write(keys.toPath(), Files.readAllBytes(new File(known.getPath()+".pub").toPath()), java.nio.file.StandardOpenOption.APPEND);

		// The server knows the key: then (and only then) the passphrase is asked; a wrong one is asked again
		TestTerminal t = new TestTerminal("", "wrong", "pass phrase");
		assertEquals(0, run(t, args("-o", "StrictHostKeyChecking=accept-new", "-i", stranger.getPath(), "-i", known.getPath(),
				"alice@localhost", "whoami")), t.stderr());
		assertEquals("alice", t.stdout());
		assertEquals(Arrays.asList("Enter passphrase for key '"+known+"': ", "Enter passphrase for key '"+known+"': "), t.prompts);

		// Without the .pub file the passphrase is asked first
		new File(known.getPath()+".pub").delete();
		t = new TestTerminal("", "pass phrase");
		assertEquals(0, run(t, args("-i", known.getPath(), "alice@localhost", "whoami")), t.stderr());
		assertEquals(1, t.prompts.size());
	}

	private static boolean keygen(File file, String passphrase) {
		try {
			Process p = new ProcessBuilder("ssh-keygen", "-q", "-t", "ed25519", "-N", passphrase, "-f", file.getPath())
					.redirectErrorStream(true).start();
			p.getInputStream().readAllBytes();
			return p.waitFor(30, TimeUnit.SECONDS) && p.exitValue() == 0;
		} catch (IOException | InterruptedException e) {
			return false;
		}
	}

	@Test
	public void interactiveShell() throws Exception {
		start();
		PipedOutputStream keys = new PipedOutputStream();
		TestTerminal tty = new TestTerminal(new PipedInputStream(keys), "secret");
		tty.terminal = true;
		TestTerminal t = tty;
		Thread typing = new Thread(() -> {
			try {
				tty.waitFor("ready");
				keys.write("one\r".getBytes(StandardCharsets.UTF_8));
				tty.waitFor("> one");
				tty.size = new int[] {120, 40};
				tty.resize.run();
				Thread.sleep(300);
				// ~~ at a line start sends one ~; ~? is help (not sent)
				keys.write("~~two\r~?three\r".getBytes(StandardCharsets.UTF_8));
				tty.waitFor("> three");
				keys.write("~.".getBytes(StandardCharsets.UTF_8));
			} catch (Exception e) {
				e.printStackTrace();
			}
		});
		typing.start();
		int status = run(t, args("-o", "StrictHostKeyChecking=accept-new", "alice@localhost"));
		typing.join(10000);
		assertEquals(255, status, "~. disconnects: "+t.stderr());
		String out = t.stdout();
		assertTrue(out.contains(" 100x30> one"), out);
		assertTrue(out.contains(" 120x40> ~two"), out);
		assertTrue(out.contains(" 120x40> three"), out);
		assertTrue(t.stderr().contains("Supported escape sequences:"), t.stderr());
		assertTrue(t.stderr().contains("Connection to localhost closed."), t.stderr());
		assertTrue(t.raw);
		assertTrue(t.restored, "the terminal is put back");

		// A shell that exits: its status, and no escape for a non-terminal stdin without -t
		TestTerminal t2 = new TestTerminal("~.\nexit\n", "secret");
		assertEquals(4, run(t2, args("alice@localhost")), t2.stderr());
		assertFalse(t2.raw);
		assertTrue(t2.stdout().contains("> ~."), t2.stdout());
		// -tt: a terminal anyway
		t2 = new TestTerminal("exit\n", "secret");
		assertEquals(4, run(t2, args("-tt", "alice@localhost")), t2.stderr());
		assertFalse(t2.raw, "stdin isn't a terminal: not raw");
		assertTrue(t2.stderr().contains("Connection to localhost closed."), t2.stderr());
		t2 = new TestTerminal("exit\n", "secret");
		assertEquals(4, run(t2, args("-t", "alice@localhost")), t2.stderr());
		assertTrue(t2.stderr().contains("Pseudo-terminal will not be allocated"), t2.stderr());
	}

	@Test
	public void localForwarding() throws Exception {
		start();
		try (ServerSocket target = new ServerSocket(0); ServerSocket probe = new ServerSocket(0)) {
			int listen = probe.getLocalPort();
			probe.close();
			Thread echo = new Thread(() -> {
				try (Socket s = target.accept()) {
					s.getOutputStream().write("forwarded\n".getBytes(StandardCharsets.UTF_8));
					s.getOutputStream().flush();
					s.getInputStream().read();
				} catch (IOException e) {
					// done
				}
			});
			echo.start();
			PipedOutputStream keys = new PipedOutputStream();
			TestTerminal t = new TestTerminal(new PipedInputStream(keys), "secret");
			Thread runner = new Thread(() -> run(t, args("-o", "StrictHostKeyChecking=accept-new",
					"-L", "127.0.0.1:"+listen+":127.0.0.1:"+target.getLocalPort(), "alice@localhost", "cat")));
			runner.start();
			String got = null;
			for (int i = 0; i < 100 && got == null; i++) {
				try (Socket c = new Socket("127.0.0.1", listen)) {
					got = new BufferedReader(new InputStreamReader(c.getInputStream(), StandardCharsets.UTF_8)).readLine();
				} catch (IOException e) {
					Thread.sleep(100);
				}
			}
			assertEquals("forwarded", got);
			keys.close();
			runner.join(10000);
			assertFalse(runner.isAlive());
		}
	}

	@Test
	public void usageAndErrors() throws Exception {
		TestTerminal t = new TestTerminal("");
		assertEquals(255, run(t, Arrays.asList("-Z", "h")));
		assertTrue(t.stderr().startsWith("ssh: unknown option -- Z"), t.stderr());
		assertTrue(t.stderr().contains("usage: ssh"), t.stderr());
		t = new TestTerminal("");
		assertEquals(0, run(t, Arrays.asList("-V")));
		assertTrue(t.stderr().startsWith("Parley SSH client"), t.stderr());
		t = new TestTerminal("");
		assertEquals(255, run(t, Arrays.asList("-F", new File(dir, "nope").getPath(), "h")));
		assertTrue(t.stderr().contains("Can't open user config file"), t.stderr());

		// Nothing listens there
		int port;
		try (ServerSocket s = new ServerSocket(0)) {
			port = s.getLocalPort();
		}
		t = new TestTerminal("");
		assertEquals(255, run(t, Arrays.asList("-F", "none", "-p", String.valueOf(port), "127.0.0.1", "true")));
		assertTrue(t.stderr().contains("ssh: connect to host 127.0.0.1 port "+port+": Connection refused"), t.stderr());
	}

	// ------------------------------------------------------------------ the stand-in terminal

	private static File write(File f, String text) throws IOException {
		Files.write(f.toPath(), text.getBytes(StandardCharsets.UTF_8));
		return f;
	}

	static final class TestTerminal extends CliTerminal {
		private final InputStream in;
		private final ByteArrayOutputStream out = new ByteArrayOutputStream();
		private final ByteArrayOutputStream errBytes = new ByteArrayOutputStream();
		private final PrintStream err = new PrintStream(errBytes, true);
		private final Deque<String> answers;
		final List<String> prompts = new ArrayList<String>();
		volatile boolean terminal;
		volatile boolean raw;
		volatile boolean restored;
		volatile int[] size = {100, 30};
		volatile Runnable resize;

		TestTerminal(String stdin, String... answers) {
			this(new ByteArrayInputStream(stdin.getBytes(StandardCharsets.UTF_8)), answers);
		}

		TestTerminal(InputStream stdin, String... answers) {
			this.in = stdin;
			this.answers = new ArrayDeque<String>(Arrays.asList(answers));
		}

		String stdout() {
			synchronized (out) {
				return new String(out.toByteArray(), StandardCharsets.UTF_8);
			}
		}

		String stderr() {
			return new String(errBytes.toByteArray(), StandardCharsets.UTF_8);
		}

		void waitFor(String text) throws InterruptedException {
			for (int i = 0; i < 200 && !stdout().contains(text); i++) {
				Thread.sleep(50);
			}
		}

		@Override
		InputStream in() {
			return in;
		}

		@Override
		OutputStream out() {
			return new OutputStream() {
				@Override
				public void write(int b) {
					synchronized (out) {
						out.write(b);
					}
				}

				@Override
				public void write(byte[] b, int off, int len) {
					synchronized (out) {
						out.write(b, off, len);
					}
				}
			};
		}

		@Override
		PrintStream err() {
			return err;
		}

		@Override
		boolean stdinIsTerminal() {
			return terminal;
		}

		@Override
		boolean enterRawMode() {
			raw = true;
			return true;
		}

		@Override
		void restore() {
			if( raw ) {
				restored = true;
			}
		}

		@Override
		int[] size() {
			return size;
		}

		@Override
		void onResize(Runnable listener) {
			resize = listener;
		}

		@Override
		synchronized char[] prompt(String prompt, boolean echo) {
			prompts.add(prompt);
			String a = answers.poll();
			return a == null ? null : a.toCharArray();
		}
	}
}
