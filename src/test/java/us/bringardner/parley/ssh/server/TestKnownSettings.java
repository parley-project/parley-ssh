package us.bringardner.parley.ssh.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Properties;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import us.bringardner.parley.net.server.KnownSettings;
import us.bringardner.parley.ssh.client.ClientSession;
import us.bringardner.parley.ssh.client.HostKeyVerifiers;
import us.bringardner.parley.ssh.client.PasswordAuth;
import us.bringardner.parley.ssh.client.SshClient;
import us.bringardner.parley.ssh.sftp.SftpClient;

/**
 * To-Do 2.16: parley-ssh's list of settings (META-INF/parley/settings.list) has every name its code
 * spells out, and every name the SSH server reads while it is set up as a service (SshServer's main),
 * starts and serves an SFTP session, so its start-up check never warns about a real setting.
 */
public class TestKnownSettings {

	@TempDir
	File dir;

	@Test
	public void everyConstantIsListed() throws Exception {
		assertEquals(List.of(), KnownSettings.load().undeclared(KnownSettings.settingConstants(SshServer.class)));
	}

	@Test
	public void everyNameTheServerReadsIsListed() throws Exception {
		KnownSettings k = KnownSettings.load();
		assertTrue(k.prefixes().contains(SshServer.PROPERTY_PREFIX), k.prefixes().toString());
		File homes = new File(dir, "homes");
		assertTrue(new File(homes, "alice").mkdirs());
		File conf = new File(dir, "conf");
		assertTrue(conf.mkdirs());
		Properties before = System.getProperties();
		KnownSettings.RecordingProperties system = new KnownSettings.RecordingProperties(before);
		int port = freePort();
		system.setProperty(SshServer.PROPERTY_PREFIX + ".port", "" + port);
		system.setProperty(SshServer.PROPERTY_PREFIX + "." + ServiceSetup.PROPERTY_HOMES, homes.getPath());
		System.setProperties(system);
		SshServer server = new SshServer(ServiceSetup.DEFAULT_PORT);
		SshClient client = new SshClient();
		try {
			new ServiceSetup(conf, false, false).configure(server);
			server.setPasswordAuthenticator((user, pw, ctx) -> "secret".equals(new String(pw)) ? new SshPrincipal(user) : null);
			server.startAndWait(5000);
			client.setHostKeyVerifier(HostKeyVerifiers.acceptAll());
			ClientSession s = client.connectAndWait("localhost", port);
			s.authenticateAndWait("alice", new PasswordAuth("secret"));
			SftpClient sftp = SftpClient.open(s);
			try (OutputStream out = sftp.write("/a.txt", false)) {
				out.write("hello".getBytes(StandardCharsets.UTF_8));
			}
			sftp.list("/");
		} finally {
			client.close();
			server.stop(5000, false);
			System.setProperties(before);
		}
		assertEquals(List.of(), k.undeclared(system.asked()));
	}

	private static int freePort() throws Exception {
		try (ServerSocket s = new ServerSocket(0)) {
			return s.getLocalPort();
		}
	}
}
