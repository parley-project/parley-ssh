package us.bringardner.parley.ssh.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.util.List;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import us.bringardner.parley.ssh.client.ClientSession;
import us.bringardner.parley.ssh.client.HostKeyVerifiers;
import us.bringardner.parley.ssh.client.PasswordAuth;
import us.bringardner.parley.ssh.client.SessionChannel;
import us.bringardner.parley.ssh.client.SshClient;

/**
 * The shellCommand property: a program to run as the shell, on a real pseudo terminal when the
 * client asks for one (so a shell such as fsh, run as its own program, has job control).
 */
public class ShellCommandTest {

	private static final String PROPERTY = SshServer.PROPERTY_PREFIX+"."+SshServer.PROPERTY_SHELL_COMMAND;

	private SshServer server;
	private SshClient client;

	@AfterEach
	public void stop() throws Exception {
		System.clearProperty(PROPERTY);
		if( client != null ) {
			client.close();
		}
		if( server != null ) {
			server.stop(5000, false);
		}
	}

	@Test
	public void commandLineIsSplitAtBlanks() {
		assertEquals(List.of("/opt/fsh/bin/fsh", "-i", "-l"), SshServer.splitCommandLine("/opt/fsh/bin/fsh -i -l"));
		assertEquals(List.of("a", "b c", "d"), SshServer.splitCommandLine("  a   \"b c\"\td  "));
		assertEquals(List.of("a b", "\"c"), SshServer.splitCommandLine("a\\ b \\\"c"));
		assertEquals(List.of("", "x"), SshServer.splitCommandLine("\"\" x"), "an empty argument");
		assertThrows(IllegalStateException.class, () -> SshServer.splitCommandLine("a \"b"));
	}

	@Test
	public void theShellIsTheCommandOnAPty() throws Exception {
		assumeTrue(!System.getProperty("os.name").toLowerCase().contains("win"), "Unix commands");
		assumeTrue(ProcessCommandFactory.isPtySupported(), "pty4j");
		// A program that says it was run, whether it has a terminal, its size, and whether it leads a session
		System.setProperty(PROPERTY, "/bin/sh -c \"echo SHELL-WAS-RUN; tty; stty size; ps -o sid=,pid= -p $$; exit 5\"");
		server = new SshServer(0);
		server.setHostKeyProvider(HostKeyProviders.ephemeral());
		server.setPasswordAuthenticator((user, pw, ctx) -> "secret".equals(new String(pw)) ? new SshPrincipal(user) : null);
		server.setLoginFailureDelay(0);
		server.startAndWait(5000);
		assertTrue(server.getShellFactory() instanceof ProcessShellFactory, "made from the property");

		client = new SshClient();
		client.setHostKeyVerifier(HostKeyVerifiers.acceptAll());
		ClientSession s = client.connectAndWait("localhost", server.getLocalPort());
		s.authenticateAndWait("alice", new PasswordAuth("secret"));
		SessionChannel ch = s.openSession();
		ch.requestPty("xterm", 100, 30);
		ch.shell();
		String out = ProcessPtyTest.readUntil(ch.getInputStream(), "30 100", 15000);
		assertTrue(out.contains("SHELL-WAS-RUN"), out);
		assertTrue(out.contains("/dev/tty") || out.contains("/dev/pts"), "a terminal: "+out);
		assertEquals(5, ch.waitForExit(15, TimeUnit.SECONDS), "the program's exit status");
		s.close();
	}

	@Test
	public void shellFactoryNamedAsAClassWins() throws Exception {
		System.setProperty(PROPERTY, "/bin/sh");
		System.setProperty(SshServer.PROPERTY_PREFIX+"."+SshServer.PROPERTY_SHELL_FACTORY, "none");
		try {
			server = new SshServer(0);
			assertEquals(null, server.getShellFactory(), "shellFactory=none turns the shell off whatever shellCommand says");
		} finally {
			System.clearProperty(SshServer.PROPERTY_PREFIX+"."+SshServer.PROPERTY_SHELL_FACTORY);
		}
	}
}
