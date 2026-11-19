package us.bringardner.parley.ssh.sftp.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.attribute.FileTime;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import us.bringardner.parley.files.fileproxy.FileProxyFactory;
import us.bringardner.parley.ssh.client.ClientSession;
import us.bringardner.parley.ssh.client.HostKeyVerifiers;
import us.bringardner.parley.ssh.client.PasswordAuth;
import us.bringardner.parley.ssh.client.SshClient;
import us.bringardner.parley.ssh.server.HostKeyProviders;
import us.bringardner.parley.ssh.server.SshServer;
import us.bringardner.parley.ssh.server.TestUsers;
import us.bringardner.parley.ssh.sftp.SftpAttrs;
import us.bringardner.parley.ssh.sftp.SftpClient;
import us.bringardner.parley.ssh.sftp.SftpConstants;
import us.bringardner.parley.ssh.sftp.SftpException;

/**
 * STAT and SETSTAT follow a symbolic link, LSTAT and lsetstat@openssh.com don't (D78): the
 * FileSource of a link answers for the link itself, and the server asks it the right question.
 */
public class SftpServerLinkAttributesTest {

	private static final long OLD = 1_500_000_000L;
	private static final long LINK_TIME = 1_600_000_000L;

	@TempDir
	File dir;
	private File root;
	private SshServer server;
	private SshClient client;
	private SftpClient sftp;

	@BeforeEach
	public void start() throws Exception {
		root = new File(dir, "root");
		assertTrue(root.mkdirs());
		File real = new File(root, "real.txt");
		Files.write(real.toPath(), "real content".getBytes(StandardCharsets.UTF_8));
		Files.setLastModifiedTime(real.toPath(), FileTime.fromMillis(OLD * 1000));
		File link = new File(root, "link");
		Files.createSymbolicLink(link.toPath(), real.toPath());
		try {
			Files.getFileAttributeView(link.toPath(), java.nio.file.attribute.BasicFileAttributeView.class, LinkOption.NOFOLLOW_LINKS)
					.setTimes(FileTime.fromMillis(LINK_TIME * 1000), FileTime.fromMillis(LINK_TIME * 1000), null);
		} catch (UnsupportedOperationException e) {
			org.junit.jupiter.api.Assumptions.assumeTrue(false, "can't set a link's own times here");
		}
		Files.createSymbolicLink(new File(root, "dangling").toPath(), new File(root, "nothing-here").toPath());

		server = new SshServer(0);
		server.setHostKeyProvider(HostKeyProviders.ephemeral());
		server.setUserRegistry(new TestUsers());
		server.addSubsystem(SftpSubsystemFactory.forRoot(new FileProxyFactory().createFileSource(root.getCanonicalPath())));
		server.startAndWait(5000);
		client = new SshClient();
		client.setHostKeyVerifier(HostKeyVerifiers.acceptAll());
		ClientSession s = client.connectAndWait("localhost", server.getLocalPort());
		s.authenticateAndWait("alice", new PasswordAuth("secret"));
		sftp = SftpClient.open(s);
	}

	@AfterEach
	public void stop() throws Exception {
		if( sftp != null ) {
			sftp.close();
		}
		if( client != null ) {
			client.close();
		}
		if( server != null ) {
			server.stop(5000, false);
		}
	}

	private long linkTime() throws Exception {
		return Files.getLastModifiedTime(new File(root, "link").toPath(), LinkOption.NOFOLLOW_LINKS).toMillis() / 1000;
	}

	private long targetTime() throws Exception {
		return Files.getLastModifiedTime(new File(root, "real.txt").toPath()).toMillis() / 1000;
	}

	@Test
	public void theServerOffersTheExtension() {
		assertTrue(sftp.hasExtension(SftpConstants.EXT_LSETSTAT));
	}

	@Test
	public void lstatIsTheLinksOwnAndStatIsWhatItLeadsTo() throws Exception {
		SftpAttrs own = sftp.lstat("/link");
		assertTrue(own.isSymbolicLink());
		assertEquals(Files.readAttributes(new File(root, "link").toPath(), java.nio.file.attribute.BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS).size(),
				own.getSize(), "the length of the link's text");
		assertEquals(LINK_TIME, own.getModifyTime(), "the link's own time");

		SftpAttrs followed = sftp.stat("/link");
		assertTrue(followed.isRegularFile());
		assertEquals(12, followed.getSize(), "what it leads to");
		assertEquals(OLD, followed.getModifyTime(), "its time");
		assertEquals(OLD, sftp.stat("/real.txt").getModifyTime());
		assertTrue(sftp.lstat("/dangling").isSymbolicLink());
		assertEquals(SftpConstants.SSH_FX_NO_SUCH_FILE, assertThrows(SftpException.class, () -> sftp.stat("/dangling")).getStatus());
	}

	@Test
	public void lsetstatChangesTheLinkNotWhatItLeadsTo() throws Exception {
		long when = 1_700_000_000L;
		sftp.lsetStat("/link", SftpAttrs.NONE.withTimes(when, when));
		assertEquals(when, linkTime());
		assertEquals(OLD, targetTime());
		assertEquals(when, sftp.lstat("/link").getModifyTime());
		// and one that leads nowhere
		sftp.lsetStat("/dangling", SftpAttrs.NONE.withTimes(when, when));
		assertEquals(when, sftp.lstat("/dangling").getModifyTime());
	}

	@Test
	public void setstatStillFollowsTheLink() throws Exception {
		long when = 1_700_000_000L;
		sftp.setStat("/link", SftpAttrs.NONE.withTimes(when, when));
		assertEquals(when, targetTime(), "what it leads to");
		assertEquals(LINK_TIME, linkTime(), "the link is as it was");
	}

	@Test
	public void aLinkHasNoModeOrOwnerOfItsOwnToChange() throws Exception {
		assertEquals(SftpConstants.SSH_FX_OP_UNSUPPORTED,
				assertThrows(SftpException.class, () -> sftp.lsetStat("/link", SftpAttrs.NONE.withPermissions(0600))).getStatus());
		assertEquals(SftpConstants.SSH_FX_OP_UNSUPPORTED,
				assertThrows(SftpException.class, () -> sftp.lsetStat("/link", SftpAttrs.NONE.withOwner(1234, 1234))).getStatus());
		assertEquals(LINK_TIME, linkTime());
	}

	@Test
	public void lsetstatOnAFileIsSetstat() throws Exception {
		long when = 1_700_000_000L;
		sftp.lsetStat("/real.txt", SftpAttrs.NONE.withTimes(when, when));
		assertEquals(when, targetTime());
		assertFalse(Files.isSymbolicLink(new File(root, "real.txt").toPath()));
		assertNotEquals(OLD, targetTime());
		assertEquals(SftpConstants.SSH_FX_NO_SUCH_FILE,
				assertThrows(SftpException.class, () -> sftp.lsetStat("/missing", SftpAttrs.NONE.withTimes(when, when))).getStatus());
	}
}
