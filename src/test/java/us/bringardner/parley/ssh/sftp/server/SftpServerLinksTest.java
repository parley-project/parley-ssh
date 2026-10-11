package us.bringardner.parley.ssh.sftp.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.List;
import java.util.stream.Collectors;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import us.bringardner.parley.files.FileSource;
import us.bringardner.parley.files.fileproxy.FileProxyFactory;
import us.bringardner.parley.files.memory.MemoryFileSourceFactory;
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

/**
 * How the SFTP server treats links, which is what the README says. SFTP is aware of links: a
 * client can see them (lstat, a listing), read them (readlink) and make them (symlink, hardlink), so
 * nothing is hidden, and what a write does follows the link, as on any file system. The root is a
 * sandbox: a link that leads outside it is seen and removable, never followed (SftpServerTest).
 */
public class SftpServerLinksTest {

	@TempDir
	File dir;
	private SshServer server;
	private SshClient client;
	private SftpSubsystemFactory sftpFactory;

	private void start(FileSource root) throws Exception {
		server = new SshServer(0);
		server.setHostKeyProvider(HostKeyProviders.ephemeral());
		server.setPasswordAuthenticator((user, pw, ctx) -> "secret".equals(new String(pw)) ? new SshPrincipal(user) : null);
		sftpFactory = SftpSubsystemFactory.forRoot(root);
		server.addSubsystem(sftpFactory);
		server.startAndWait(5000);
	}

	private SftpClient sftp() throws Exception {
		client = new SshClient();
		client.setHostKeyVerifier(HostKeyVerifiers.acceptAll());
		ClientSession s = client.connectAndWait("localhost", server.getLocalPort());
		s.authenticateAndWait("alice", new PasswordAuth("secret"));
		return SftpClient.open(s);
	}

	@AfterEach
	public void stop() throws Exception {
		if( client != null ) {
			client.close();
		}
		if( server != null ) {
			server.stop(5000, false);
		}
	}

	/** real.txt (12 bytes) and realdir/inner.txt, with link and dirlink leading to them, and a dangling one */
	private File tree() throws Exception {
		File root = new File(dir, "root");
		assertTrue(root.mkdirs());
		Files.write(new File(root, "real.txt").toPath(), "real content".getBytes(StandardCharsets.UTF_8));
		assertTrue(new File(root, "realdir").mkdir());
		Files.write(new File(root, "realdir/inner.txt").toPath(), "inner".getBytes(StandardCharsets.UTF_8));
		Files.createSymbolicLink(new File(root, "link").toPath(), new File(root, "real.txt").toPath());
		Files.createSymbolicLink(new File(root, "dirlink").toPath(), new File(root, "realdir").toPath());
		Files.createSymbolicLink(new File(root, "dangling").toPath(), new File(root, "nothing-here").toPath());
		start(new FileProxyFactory().createFileSource(root.getCanonicalPath()));
		return root;
	}

	private static String read(File f) throws Exception {
		return new String(Files.readAllBytes(f.toPath()), StandardCharsets.UTF_8);
	}

	private static void put(SftpClient sftp, String path, String data, boolean append) throws Exception {
		try (OutputStream out = sftp.write(path, append)) {
			out.write(data.getBytes(StandardCharsets.UTF_8));
		}
	}

	@Test
	public void aListingAndLstatShowALinkAsALinkAndStatFollowsIt() throws Exception {
		tree();
		try (SftpClient sftp = sftp()) {
			List<SftpDirEntry> entries = sftp.list("/");
			java.util.Map<String, SftpDirEntry> byName = entries.stream().collect(Collectors.toMap(SftpDirEntry::getName, e -> e, (a, b) -> a));
			assertTrue(byName.get("link").getAttrs().isSymbolicLink(), "a listing says it is a link");
			assertTrue(byName.get("link").getLongName().startsWith("l"), byName.get("link").getLongName());
			assertTrue(byName.get("dirlink").getAttrs().isSymbolicLink());
			assertTrue(byName.get("dangling").getAttrs().isSymbolicLink(), "also one that leads nowhere");
			assertTrue(byName.get("real.txt").getAttrs().isRegularFile());
			assertTrue(byName.get("realdir").getAttrs().isDirectory());

			assertTrue(sftp.lstat("/link").isSymbolicLink());
			assertTrue(sftp.stat("/link").isRegularFile(), "stat follows it");
			assertEquals(12, sftp.stat("/link").getSize(), "the size of what it leads to");
			assertTrue(sftp.stat("/dirlink").isDirectory());
			assertEquals(List.of(".", "..", "inner.txt"),
					sftp.list("/dirlink").stream().map(SftpDirEntry::getName).collect(Collectors.toList()), "a linked directory lists what it leads to");
			assertEquals("/real.txt", sftp.readlink("/link"), "readlink gives the client's path");
		}
	}

	@Test
	public void aWriteThroughALinkChangesWhatItLeadsToAndTheLinkStaysALink() throws Exception {
		File root = tree();
		try (SftpClient sftp = sftp()) {
			put(sftp, "/link", "NEW", false);
			assertEquals("NEW", read(new File(root, "real.txt")), "the original changed");
			assertTrue(Files.isSymbolicLink(new File(root, "link").toPath()), "and the link is still a link");

			put(sftp, "/link", "+more", true);
			assertEquals("NEW+more", read(new File(root, "real.txt")));

			// through a linked directory
			put(sftp, "/dirlink/created.txt", "x", false);
			assertEquals("x", read(new File(root, "realdir/created.txt")));
		}
	}

	@Test
	public void setStatThroughALinkChangesWhatItLeadsTo() throws Exception {
		File root = tree();
		try (SftpClient sftp = sftp()) {
			sftp.setStat("/link", SftpAttrs.NONE.withSize(4));
			assertEquals(4, new File(root, "real.txt").length(), "truncated the original");
			sftp.setStat("/link", SftpAttrs.NONE.withPermissions(0640));
			if( new File(root, "real.txt").toPath().getFileSystem().supportedFileAttributeViews().contains("posix") ) {
				assertEquals("rw-r-----", java.nio.file.attribute.PosixFilePermissions.toString(
						Files.getPosixFilePermissions(new File(root, "real.txt").toPath())));
			}
			assertTrue(Files.isSymbolicLink(new File(root, "link").toPath()));
		}
	}

	@Test
	public void removeAndRenameActOnTheLinkAndNotWhatItLeadsTo() throws Exception {
		File root = tree();
		try (SftpClient sftp = sftp()) {
			sftp.rename("/link", "/link-renamed");
			assertTrue(Files.isSymbolicLink(new File(root, "link-renamed").toPath()), "the link moved");
			assertFalse(Files.isSymbolicLink(new File(root, "link").toPath()));
			assertEquals("real content", read(new File(root, "real.txt")), "the original is where it was");
			assertEquals("real content", read(new File(root, "link-renamed")), "and the link still leads to it");

			sftp.remove("/link-renamed");
			assertFalse(Files.isSymbolicLink(new File(root, "link-renamed").toPath()));
			assertEquals("real content", read(new File(root, "real.txt")));

			// a link to a directory is removed with remove, not rmdir
			// (version 3, the default, has no "not a directory" status, so it's a plain failure)
			assertThrows(SftpException.class, () -> sftp.rmdir("/dirlink"));
			assertTrue(Files.isSymbolicLink(new File(root, "dirlink").toPath()), "rmdir didn't remove the link");
			sftp.remove("/dirlink");
			assertFalse(Files.isSymbolicLink(new File(root, "dirlink").toPath()));
			assertEquals("inner", read(new File(root, "realdir/inner.txt")), "the directory and its contents are kept");
		}
	}

	/**
	 * What OpenSSH's sftp-server answers (every case here was put to /usr/libexec/sftp-server): links are
	 * resolved, as realpath(3), and only the last component may be missing.
	 */
	@Test
	public void realpathResolvesLinksAsOpenSshDoes() throws Exception {
		File root = tree();
		// a link with a relative target, one in a directory that goes up, a chain, and a loop
		Files.createSymbolicLink(new File(root, "rel").toPath(), java.nio.file.Paths.get("real.txt"));
		assertTrue(new File(root, "sub").mkdir());
		Files.createSymbolicLink(new File(root, "sub/up").toPath(), java.nio.file.Paths.get("../realdir"));
		Files.createSymbolicLink(new File(root, "chain1").toPath(), java.nio.file.Paths.get("chain2"));
		Files.createSymbolicLink(new File(root, "chain2").toPath(), java.nio.file.Paths.get("real.txt"));
		Files.createSymbolicLink(new File(root, "loopa").toPath(), java.nio.file.Paths.get("loopb"));
		Files.createSymbolicLink(new File(root, "loopb").toPath(), java.nio.file.Paths.get("loopa"));
		try (SftpClient sftp = sftp()) {
			assertEquals("/real.txt", sftp.realpath("/real.txt"));
			assertEquals("/real.txt", sftp.realpath("/link"), "a link is resolved");
			assertEquals("/real.txt", sftp.realpath("/rel"), "also one with a relative target");
			assertEquals("/real.txt", sftp.realpath("/chain1"), "and a chain of them");
			assertEquals("/realdir", sftp.realpath("/dirlink"));
			assertEquals("/realdir/inner.txt", sftp.realpath("/dirlink/inner.txt"), "a link in the middle of the path");
			assertEquals("/realdir", sftp.realpath("/sub/up"), "a relative target that goes up");
			assertEquals("/nothing-here", sftp.realpath("/dangling"), "one that leads nowhere resolves to the name it leads to");
			// ".." after a link is the parent of where the link leads, not of the link
			assertEquals("/", sftp.realpath("/sub/up/.."));
			assertEquals("/", sftp.realpath("/dirlink/.."));
			assertEquals("/real.txt", sftp.realpath("/dirlink/../real.txt"));
			// only the last component may be missing, and ".." can't climb above "/"
			assertEquals("/new", sftp.realpath("/new"));
			assertEquals("/", sftp.realpath("/../../.."));
			assertEquals("/", sftp.realpath("."));
			SftpException e = assertThrows(SftpException.class, () -> sftp.realpath("/new/file.txt"));
			assertEquals(SftpConstants.SSH_FX_NO_SUCH_FILE, e.getStatus(), "a missing directory in the middle");
			e = assertThrows(SftpException.class, () -> sftp.realpath("/new/"));
			assertEquals(SftpConstants.SSH_FX_NO_SUCH_FILE, e.getStatus(), "a missing name that is followed by a slash");
			// a loop: OpenSSH answers "no such file"
			e = assertThrows(SftpException.class, () -> sftp.realpath("/loopa"));
			assertEquals(SftpConstants.SSH_FX_NO_SUCH_FILE, e.getStatus());
		}
	}

	@Test
	public void realpathOfALinkThatLeadsOutsideTheRootIsRefused() throws Exception {
		File root = tree();
		File outside = new File(dir, "outside.txt");
		Files.write(outside.toPath(), "outside".getBytes(StandardCharsets.UTF_8));
		Files.createSymbolicLink(new File(root, "escape").toPath(), outside.toPath());
		Files.createSymbolicLink(new File(root, "escapedir").toPath(), dir.toPath());
		try (SftpClient sftp = sftp()) {
			SftpException e = assertThrows(SftpException.class, () -> sftp.realpath("/escape"));
			assertEquals(SftpConstants.SSH_FX_PERMISSION_DENIED, e.getStatus(), "it doesn't say where it leads");
			e = assertThrows(SftpException.class, () -> sftp.realpath("/escapedir/anything"));
			assertEquals(SftpConstants.SSH_FX_PERMISSION_DENIED, e.getStatus());
			// the answer never holds the server's real path
			assertFalse(sftp.realpath("/link").contains(dir.getName()));
		}
	}

	@Test
	public void aLinkThatLeadsNowhereIsSeenAndCanBeRemoved() throws Exception {
		File root = tree();
		try (SftpClient sftp = sftp()) {
			assertTrue(sftp.lstat("/dangling").isSymbolicLink());
			SftpException e = assertThrows(SftpException.class, () -> sftp.stat("/dangling"));
			assertEquals(SftpConstants.SSH_FX_NO_SUCH_FILE, e.getStatus(), "stat follows it, and there is nothing there");
			assertEquals("/nothing-here", sftp.readlink("/dangling"));
			sftp.remove("/dangling");
			assertFalse(Files.isSymbolicLink(new File(root, "dangling").toPath()));
		}
	}

	@Test
	public void linksCanBeMadeAndTheyAreRealLinks() throws Exception {
		File root = tree();
		try (SftpClient sftp = sftp()) {
			sftp.symlink("real.txt", "/made");              // OpenSSH's order: the target, then the link
			assertTrue(Files.isSymbolicLink(new File(root, "made").toPath()));
			assertEquals("/real.txt", sftp.readlink("/made"));
			sftp.hardlink("/real.txt", "/hard");
			put(sftp, "/hard", "via hard link", false);
			assertEquals("via hard link", read(new File(root, "real.txt")), "a hard link is the same file");
			assertThrows(SftpException.class, () -> sftp.symlink("real.txt", "/made"), "a link that is there");
		}
	}

	@Test
	public void readOnlyModeRefusesToMakeOrChangeLinks() throws Exception {
		File root = tree();
		sftpFactory.setReadOnly(true);
		try (SftpClient sftp = sftp()) {
			assertThrows(SftpException.class, () -> sftp.symlink("real.txt", "/made"));
			assertThrows(SftpException.class, () -> sftp.remove("/link"));
			assertThrows(SftpException.class, () -> sftp.rename("/link", "/other"));
			assertThrows(SftpException.class, () -> put(sftp, "/link", "x", false));
			// reading still works, through the link
			try (InputStream in = sftp.read("/link", 0)) {
				assertEquals("real content", new String(in.readAllBytes(), StandardCharsets.UTF_8));
			}
		}
		assertTrue(Files.isSymbolicLink(new File(root, "link").toPath()));
		assertEquals("real content", read(new File(root, "real.txt")));
	}

	@Test
	public void anyFileSourceCanBeTheRootAndLinksFollowItsRules() throws Exception {
		FileSource root = new MemoryFileSourceFactory().createFileSource("/");
		FileSource real = root.getChild("real.txt");
		try (OutputStream out = real.getOutputStream()) {
			out.write("memory".getBytes(StandardCharsets.UTF_8));
		}
		start(root);
		try (SftpClient sftp = sftp()) {
			sftp.symlink("real.txt", "/ln");
			assertTrue(sftp.lstat("/ln").isSymbolicLink());
			assertEquals(6, sftp.stat("/ln").getSize());
			put(sftp, "/ln", "changed", false);
			try (InputStream in = real.getInputStream()) {
				assertEquals("changed", new String(in.readAllBytes(), StandardCharsets.UTF_8));
			}
			assertEquals("/real.txt", sftp.readlink("/ln"));
		}
	}
}
