package us.bringardner.parley.ssh.server;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import us.bringardner.parley.ssh.SshException;
import us.bringardner.parley.ssh.algorithms.SshCertificate;
import us.bringardner.parley.ssh.algorithms.SshPublicKeys;
import us.bringardner.parley.ssh.client.ClientSession;
import us.bringardner.parley.ssh.client.HostKeyVerifiers;
import us.bringardner.parley.ssh.client.PublicKeyAuth;
import us.bringardner.parley.ssh.client.SshClient;
import us.bringardner.parley.ssh.sftp.SftpClient;

/**
 * SshServer run as a service: {@link ServiceSetup} in this JVM, and {@link SshServer#main(String[])}
 * as a process of its own.
 */
public class ServiceSetupTest {

	@TempDir
	File dir;

	private File conf;
	private File homes;
	private SshServer server;
	private SshClient client;
	private final List<String> properties = new ArrayList<String>();

	@BeforeEach
	public void folders() {
		conf = new File(dir, "etc-parley");
		homes = new File(dir, "home");
		assertTrue(conf.mkdirs() && homes.mkdirs());
	}

	@AfterEach
	public void stop() throws Exception {
		if( client != null ) {
			client.close();
		}
		if( server != null ) {
			server.stop(5000, false);
		}
		for (String p : properties) {
			System.clearProperty(p);
		}
	}

	private void set(String name, String value) {
		String p = SshServer.PROPERTY_PREFIX+"."+name;
		properties.add(p);
		System.setProperty(p, value);
	}

	/** homes/USER with .ssh/authorized_keys holding the key */
	private File user(String name, KeyPair key) throws Exception {
		File home = new File(homes, name);
		File ssh = new File(home, ".ssh");
		assertTrue(ssh.mkdirs());
		if( key != null ) {
			Files.write(new File(ssh, "authorized_keys").toPath(),
					(SshPublicKeys.toOpenSsh(key.getPublic())+" "+name+"@test\n").getBytes(StandardCharsets.UTF_8));
		}
		return home;
	}

	private SshServer start() throws Exception {
		set("port", "0");
		set(ServiceSetup.PROPERTY_HOMES, homes.getPath());
		SshServer s = new SshServer(ServiceSetup.DEFAULT_PORT);
		s.setName("service-test");
		server = s;
		new ServiceSetup(conf, false, false).configure(s);
		s.startAndWait(10000);
		return s;
	}

	private ClientSession connect() throws Exception {
		client = new SshClient();
		client.setHostKeyVerifier(HostKeyVerifiers.only(server.getHostKeys().stream().map(KeyPair::getPublic).toArray(java.security.PublicKey[]::new)));
		return client.connectAndWait("localhost", server.getLocalPort());
	}

	private static boolean posix() {
		return !System.getProperty("os.name", "").toLowerCase().startsWith("windows");
	}

	@Test
	public void hostKeysAreMadeOnceInTheConfFolder() throws Exception {
		start();
		File keys = new File(conf, ServiceSetup.HOST_KEY_FOLDER);
		assertTrue(new File(keys, "ssh_host_ecdsa_key").isFile());
		assertTrue(new File(keys, "ssh_host_rsa_key.pub").isFile());
		if( posix() ) {
			assertEquals("rwx------", PosixFilePermissions.toString(Files.getPosixFilePermissions(keys.toPath())));
		}
		byte[] first = SshPublicKeys.encode(server.getHostKeys().get(0).getPublic());
		server.stop(5000, false);

		start();
		assertArrayEquals(first, SshPublicKeys.encode(server.getHostKeys().get(0).getPublic()), "a restart keeps the host keys");
	}

	@Test
	public void hostKeyDirSettingWins() throws Exception {
		File elsewhere = new File(dir, "keys");
		set(SshServer.PROPERTY_HOST_KEY_DIR, elsewhere.getPath());
		start();
		assertTrue(new File(elsewhere, "ssh_host_ecdsa_key").isFile());
		assertFalse(new File(conf, ServiceSetup.HOST_KEY_FOLDER).exists());
	}

	@Test
	public void authorizedKeysAndSftpInTheHome() throws Exception {
		KeyPair alice = CertificateTest.ec("secp256r1");
		File home = user("alice", alice);
		start();
		ClientSession s = connect();
		s.authenticateAndWait("alice", new PublicKeyAuth(alice));
		try (SftpClient sftp = SftpClient.open(s)) {
			try (OutputStream out = sftp.write("/hello.txt", false)) {
				out.write("hi".getBytes(StandardCharsets.UTF_8));
			}
			assertNotNull(sftp.stat("/.ssh/authorized_keys"), "SFTP's / is the user's home");
		}
		assertEquals("hi", new String(Files.readAllBytes(new File(home, "hello.txt").toPath()), StandardCharsets.UTF_8));
	}

	@Test
	public void anotherUsersKeyIsRefused() throws Exception {
		KeyPair alice = CertificateTest.ec("secp256r1");
		user("alice", alice);
		user("bob", CertificateTest.ec("secp256r1"));
		start();
		ClientSession s = connect();
		assertThrows(SshException.class, () -> s.authenticateAndWait("bob", new PublicKeyAuth(alice)));
	}

	@Test
	public void noSftpWithoutAHomeFolder() throws Exception {
		KeyPair carol = CertificateTest.ec("secp256r1");
		KeyPair ca = CertificateTest.ec("secp384r1");
		Files.createDirectories(new File(conf, ServiceSetup.HOST_KEY_FOLDER).toPath());
		Files.write(new File(new File(conf, ServiceSetup.HOST_KEY_FOLDER), ServiceSetup.TRUSTED_USER_CA_KEYS_FILE).toPath(),
				(SshPublicKeys.toOpenSsh(ca.getPublic())+" test-ca\n").getBytes(StandardCharsets.UTF_8));
		start();
		ClientSession s = connect();
		// (carol has a certificate but no home folder)
		s.authenticateAndWait("carol", new PublicKeyAuth().addCertificate(carol, CertificateTest.user(carol, ca, null, null, "carol")));
		assertThrows(Exception.class, () -> SftpClient.open(s));
	}

	@Test
	public void trustedUserCertificates() throws Exception {
		KeyPair dave = CertificateTest.ec("secp256r1");
		KeyPair ca = CertificateTest.ec("secp384r1");
		user("dave", null);
		File cas = new File(dir, "cas.pub");
		Files.write(cas.toPath(), (SshPublicKeys.toOpenSsh(ca.getPublic())+" test-ca\n").getBytes(StandardCharsets.UTF_8));
		set(ServiceSetup.PROPERTY_TRUSTED_USER_CA_KEYS, cas.getPath());
		start();

		ClientSession s = connect();
		s.authenticateAndWait("dave", new PublicKeyAuth().addCertificate(dave, CertificateTest.user(dave, ca, null, null, "dave")));
		try (SftpClient sftp = SftpClient.open(s)) {
			assertEquals("/", sftp.realpath("."));
		}

		// a certificate for another principal can't log in as dave
		ClientSession other = connect();
		assertThrows(SshException.class, () -> other.authenticateAndWait("dave",
				new PublicKeyAuth().addCertificate(dave, CertificateTest.user(dave, ca, null, null, "eve"))));
	}

	@Test
	public void aMissingCaFileStopsTheStart() throws Exception {
		set(ServiceSetup.PROPERTY_TRUSTED_USER_CA_KEYS, new File(dir, "nothing.pub").getPath());
		assertThrows(java.io.IOException.class, this::start);
	}

	@Test
	public void sftpRoot() {
		File h = new File("/home");
		SshPrincipal p = new SshPrincipal("frank");
		assertEquals(new File(h, "frank"), SftpSetup.rootOf(p, "frank", h));
		p.setParameter(SftpSetup.PARAMETER_USER_ROOT, "/srv/frank");
		assertEquals(new File("/srv/frank"), SftpSetup.rootOf(p, "frank", h), "the access control list's userRoot, as FTP");
		assertNull(SftpSetup.rootOf(null, "..", h));
		assertNull(SftpSetup.rootOf(null, "a/b", h));
		assertNull(SftpSetup.rootOf(null, "-x", h));
	}

	@Test
	public void defaultHomes() {
		assertEquals(new File("/home"), new ServiceSetup(conf, false, false).defaultHomes());
		assertEquals(new File("/Users"), new ServiceSetup(conf, false, true).defaultHomes());
		assertTrue(new ServiceSetup(conf, true, false).defaultHomes().getPath().endsWith("\\Users"));
	}

	// ------------------------------------------------------------------ the process

	private Process main(String... args) throws Exception {
		List<String> cmd = new ArrayList<String>();
		cmd.add(new File(System.getProperty("java.home"), "bin"+File.separator+"java").getPath());
		cmd.add("-cp");
		cmd.add(System.getProperty("java.class.path"));
		cmd.add(SshServer.class.getName());
		Collections.addAll(cmd, args);
		ProcessBuilder pb = new ProcessBuilder(cmd).redirectErrorStream(true);
		// (Parley's administrator folder: here, not /etc/parley)
		pb.environment().put("PARLEY_CONF", new File(conf, "parley.properties").getPath());
		return pb.start();
	}

	/** @return the port from "SshServer started on port N", or -1 if the process ended first */
	private static int startedPort(Process p, StringBuilder out) throws Exception {
		BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream(), StandardCharsets.UTF_8));
		String line;
		while( (line = r.readLine()) != null ) {
			out.append(line).append('\n');
			if( line.startsWith("SshServer started on port ") ) {
				return Integer.parseInt(line.substring("SshServer started on port ".length()).trim());
			}
		}
		return -1;
	}

	@Test
	public void runsAsAProcessUntilStopped() throws Exception {
		KeyPair alice = CertificateTest.ec("secp256r1");
		user("alice", alice);
		// (the settings file in the administrator folder, read without being named)
		Files.write(new File(conf, ServiceSetup.CONFIG_FILE_NAME).toPath(),
				("parley.ssh.port=0\nparley.ssh.homes="+homes.getPath().replace("\\", "\\\\")+"\n").getBytes(StandardCharsets.UTF_8));
		Process p = main();
		try {
			StringBuilder out = new StringBuilder();
			int port = startedPort(p, out);
			assertTrue(port > 0, out.toString());
			assertTrue(p.isAlive(), "the process waits while the server runs");
			assertTrue(new File(new File(conf, ServiceSetup.HOST_KEY_FOLDER), "ssh_host_ecdsa_key").isFile());

			client = new SshClient();
			client.setHostKeyVerifier(HostKeyVerifiers.acceptAll());
			ClientSession s = client.connectAndWait("localhost", port);
			s.authenticateAndWait("alice", new PublicKeyAuth(alice));
			client.close();
			client = null;

			p.destroy();	// SIGTERM, as a service manager stops it
			assertTrue(p.waitFor(20, TimeUnit.SECONDS), "the process ends when it is stopped");
		} finally {
			p.destroyForcibly();
		}
	}

	@Test
	public void exitsWithOneWhenItCannotStart() throws Exception {
		try (ServerSocket taken = new ServerSocket(0)) {
			Process p = main("-Dparley.ssh.port="+taken.getLocalPort(), "-Dparley.ssh.homes="+homes.getPath());
			try {
				assertTrue(p.waitFor(60, TimeUnit.SECONDS), "the process ends");
				assertEquals(1, p.exitValue());
			} finally {
				p.destroyForcibly();
			}
		}
	}
}
