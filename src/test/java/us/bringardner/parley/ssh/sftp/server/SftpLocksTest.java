package us.bringardner.parley.ssh.sftp.server;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import us.bringardner.parley.files.FileSource;
import us.bringardner.parley.files.fileproxy.FileProxyFactory;
import us.bringardner.parley.net.lock.LockDomain;
import us.bringardner.parley.net.lock.LockOptions;
import us.bringardner.parley.net.lock.Locks;
import us.bringardner.parley.net.lock.Mode;
import us.bringardner.parley.net.lock.NamedLock;
import us.bringardner.parley.net.lock.Sharing;
import us.bringardner.parley.ssh.client.ClientSession;
import us.bringardner.parley.ssh.client.HostKeyVerifiers;
import us.bringardner.parley.ssh.client.PasswordAuth;
import us.bringardner.parley.ssh.client.SshClient;
import us.bringardner.parley.ssh.server.HostKeyProviders;
import us.bringardner.parley.ssh.server.SshPrincipal;
import us.bringardner.parley.ssh.server.SshServer;
import us.bringardner.parley.ssh.sftp.SftpAttrs;
import us.bringardner.parley.ssh.sftp.SftpClient;
import us.bringardner.parley.ssh.sftp.SftpConstants;
import us.bringardner.parley.ssh.sftp.SftpDirEntry;
import us.bringardner.parley.ssh.sftp.SftpException;
import us.bringardner.parley.ssh.sftp.SftpHandle;

/** Writers keep out of each other: sessions of this server, and other servers sharing the store. */
public class SftpLocksTest {

	@TempDir
	File dir;

	private SshServer server;
	private FileSource root;
	private final List<SshClient> clients = new ArrayList<>();
	private String sharingBefore;

	private void start(Sharing sharing) throws Exception {
		sharingBefore = System.getProperty(SftpServer.SHARED_STORE_PROPERTY);
		System.setProperty(SftpServer.SHARED_STORE_PROPERTY, sharing.name().toLowerCase());
		File r = new File(dir, "root");
		assertTrue(r.mkdirs());
		root = new FileProxyFactory().createFileSource(r.getCanonicalPath());
		server = new SshServer(0);
		server.setHostKeyProvider(HostKeyProviders.ephemeral());
		server.setPasswordAuthenticator((user, pw, ctx) -> "secret".equals(new String(pw)) ? new SshPrincipal(user) : null);
		server.addSubsystem(SftpSubsystemFactory.forRoot(root));
		server.startAndWait(5000);
	}

	private SftpClient sftp() throws Exception {
		SshClient c = new SshClient();
		clients.add(c);
		c.setHostKeyVerifier(HostKeyVerifiers.acceptAll());
		ClientSession s = c.connectAndWait("localhost", server.getLocalPort());
		s.authenticateAndWait("alice", new PasswordAuth("secret"));
		return SftpClient.open(s);
	}

	@AfterEach
	public void stop() throws Exception {
		for (SshClient c : clients) {
			c.close();
		}
		if( server != null ) {
			server.stop(5000, false);
		}
		if( sharingBefore == null ) {
			System.clearProperty(SftpServer.SHARED_STORE_PROPERTY);
		} else {
			System.setProperty(SftpServer.SHARED_STORE_PROPERTY, sharingBefore);
		}
	}

	private static void put(SftpClient sftp, String path, String text) throws Exception {
		try (OutputStream out = sftp.write(path, false)) {
			out.write(text.getBytes(StandardCharsets.UTF_8));
		}
	}

	private static SftpHandle openForWrite(SftpClient sftp, String path) throws Exception {
		return sftp.open(path, SftpConstants.SSH_FXF_WRITE | SftpConstants.SSH_FXF_CREAT, SftpAttrs.NONE);
	}

	private static void assertBusy(org.junit.jupiter.api.function.Executable e, String what) {
		SftpException x = assertThrows(SftpException.class, e, what);
		assertTrue(x.getMessage().contains("another session"), what + ": " + x.getMessage());
	}

	@Test
	public void aFileBeingWrittenIsKeptFromOtherSessions() throws Exception {
		start(Sharing.OFF);
		SftpClient a = sftp();
		SftpClient b = sftp();
		put(a, "/a.txt", "old");
		SftpHandle h = openForWrite(a, "/a.txt");
		byte[] data = "new!".getBytes(StandardCharsets.UTF_8);
		a.write(h, 0, data, 0, data.length);

		assertBusy(() -> openForWrite(b, "/a.txt"), "another session can't write it");
		assertBusy(() -> b.remove("/a.txt"), "nor remove it");
		assertBusy(() -> b.rename("/a.txt", "/b.txt"), "nor rename it");
		put(b, "/c.txt", "c");
		assertBusy(() -> b.posixRename("/c.txt", "/a.txt"), "nor rename another file over it");
		SftpAttrs size = SftpAttrs.NONE.withSize(0);
		assertBusy(() -> b.setStat("/a.txt", size), "nor change its size");
		assertNotNull(b.stat("/a.txt"), "but it can look at it");
		try (java.io.InputStream in = b.read("/a.txt", 0)) {
			assertTrue(in.readAllBytes().length > 0, "and read it");
		}

		SftpHandle again = openForWrite(a, "/a.txt");
		again.close(); // the same session may open it twice
		h.close();
		put(b, "/a.txt", "b's"); // free once closed
		b.rename("/a.txt", "/d.txt");
		assertArrayEquals("b's".getBytes(StandardCharsets.UTF_8), b.read("/d.txt", 0).readAllBytes());
	}

	@Test
	public void aSessionThatEndsLetsGo() throws Exception {
		start(Sharing.OFF);
		SftpClient a = sftp();
		openForWrite(a, "/e.txt");
		clients.get(0).close(); // gone without closing the handle
		SftpClient b = sftp();
		long end = System.currentTimeMillis() + 10_000;
		while( true ) {
			try {
				openForWrite(b, "/e.txt").close();
				break;
			} catch (SftpException busy) {
				if( System.currentTimeMillis() > end ) {
					throw busy;
				}
				Thread.sleep(50);
			}
		}
	}

	@Test
	public void anotherServerSharingTheStoreIsKeptOutToo() throws Exception {
		start(Sharing.CLUSTER);
		SftpClient a = sftp();
		put(a, "/f.txt", "f");
		try (Locks other = Locks.open(LockOptions.sharing(Sharing.CLUSTER).withOwnerId("other")
				.withLease(Duration.ofSeconds(3), Duration.ofSeconds(1)))) {
			LockDomain d = other.domain("other-files", root);
			NamedLock held = d.tryLock("file/f.txt", Mode.EXCLUSIVE);
			assertNotNull(held);
			try {
				assertBusy(() -> openForWrite(a, "/f.txt"), "the other server is writing it");
				assertBusy(() -> a.remove("/f.txt"), "nor removed");
			} finally {
				held.close();
			}
			openForWrite(a, "/f.txt").close();
			SftpHandle h = openForWrite(a, "/f.txt");
			assertTrue(d.tryLock("file/f.txt", Mode.EXCLUSIVE) == null, "and the other server finds it busy");
			h.close();
		}
	}

	@Test
	public void theLockDirectoryCantBeReached() throws Exception {
		start(Sharing.OFF);
		SftpClient a = sftp();
		put(a, "/g.txt", "g");
		assertTrue(new File(root.getAbsolutePath(), Locks.DIRECTORY).isDirectory(), "the locks are kept in the root");
		for (SftpDirEntry e : a.list("/")) {
			assertFalse(e.getName().equals(Locks.DIRECTORY), "not listed");
		}
		SftpException x = assertThrows(SftpException.class, () -> a.list("/" + Locks.DIRECTORY));
		assertEquals(SftpConstants.SSH_FX_PERMISSION_DENIED, x.getStatus());
		assertThrows(SftpException.class, () -> a.remove("/" + Locks.DIRECTORY + "/regions"));
		assertThrows(SftpException.class, () -> a.rmdir("/" + Locks.DIRECTORY));
		assertThrows(SftpException.class, () -> put(a, "/" + Locks.DIRECTORY + "/x", "x"));
	}
}
