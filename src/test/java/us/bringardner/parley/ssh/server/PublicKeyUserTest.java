package us.bringardner.parley.ssh.server;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.IOException;
import java.util.Arrays;

import org.junit.jupiter.api.Test;

import us.bringardner.parley.iam.AuthenticationResult;
import us.bringardner.parley.iam.ProofVerifier;
import us.bringardner.parley.iam.Requester;
import us.bringardner.parley.iam.StoredCredential;
import us.bringardner.parley.iam.StoredCredentialType;
import us.bringardner.parley.iam.credential.ProofCredential;
import us.bringardner.parley.net.server.FileUserRegistry;

/** A public key logs in a user of the registry, never a group. */
public class PublicKeyUserTest {

	/** A key check that always says yes, as if the key were in authorized_keys and the signature good. */
	private static final ProofVerifier GOOD_KEY = new ProofVerifier() {
		@Override
		public boolean verify(StoredCredential stored) throws IOException {
			return true;
		}
	};

	private static ProofCredential key(String user) {
		Requester requester = Requester.connected(null, 22, false, Requester.Transport.TCP, "ssh");
		return new ProofCredential(user, StoredCredentialType.SSH_PUBLIC_KEYS, GOOD_KEY, requester);
	}

	@Test
	public void aGroupCantLogInWithAKey() {
		SshServer server = new SshServer(0);
		server.setUserRegistry(new FileUserRegistry() {
			{
				load(Arrays.asList("tony, secret, READ, groups=staff"));
			}
		});
		assertEquals(AuthenticationResult.Status.AUTHENTICATED, server.authenticate(key("tony")).getStatus());
		assertEquals(AuthenticationResult.Status.REFUSED, server.authenticate(key("staff")).getStatus(), "staff is a group");
		assertEquals(AuthenticationResult.Status.REFUSED, server.probe(key("staff")).getStatus());
		assertEquals(AuthenticationResult.Status.REFUSED, server.authenticate(key("nobody")).getStatus());
	}
}
