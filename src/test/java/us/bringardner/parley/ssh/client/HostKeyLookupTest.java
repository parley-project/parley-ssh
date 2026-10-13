package us.bringardner.parley.ssh.client;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.Test;

import us.bringardner.parley.ssh.algorithms.SshPublicKeys;

/**
 * HostKeyVerifiers.withLookup: an outside source (SSHFP in DNS) first, then the fallback.
 */
public class HostKeyLookupTest {

	private static PublicKey key() throws Exception {
		KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
		g.initialize(new ECGenParameterSpec("secp256r1"));
		return g.generateKeyPair().getPublic();
	}

	@Test
	public void theLookupDecidesWhenItKnows() throws Exception {
		PublicKey k = key();
		AtomicReference<byte[]> asked = new AtomicReference<byte[]>();
		IHostKeyVerifier refuseAll = (h, p, key) -> false;
		IHostKeyVerifier v = HostKeyVerifiers.withLookup((h, blob) -> {
			asked.set(blob);
			return Boolean.TRUE;
		}, refuseAll);
		assertTrue(v.verify("host.example", 22, k), "vouched for");
		assertArrayEquals(SshPublicKeys.encode(k), asked.get(), "the key in SSH wire form");
		assertFalse(HostKeyVerifiers.withLookup((h, blob) -> Boolean.FALSE, HostKeyVerifiers.acceptAll()).verify("h", 22, k),
				"refused even though the fallback would accept");
	}

	@Test
	public void theFallbackDecidesOtherwise() throws Exception {
		PublicKey k = key();
		IHostKeyVerifier fallback = HostKeyVerifiers.only(k);
		IHostKeyVerifier v = HostKeyVerifiers.withLookup((h, blob) -> null, fallback);
		assertTrue(v.verify("h", 22, k));
		assertFalse(v.verify("h", 22, key()));
		assertEquals(fallback.getKnownKeyTypes("h", 22), v.getKnownKeyTypes("h", 22));
		assertFalse(v.verifyCertificate("h", 22, null), "the fallback's (none trusted)");
		List<String> none = Collections.emptyList();
		assertEquals(none, HostKeyVerifiers.withLookup((h, b) -> null, (h, p, key) -> true).getKnownKeyTypes("h", 22));
		assertThrows(IllegalArgumentException.class, () -> HostKeyVerifiers.withLookup(null, fallback));
		assertThrows(IllegalArgumentException.class, () -> HostKeyVerifiers.withLookup((h, b) -> null, null));
		assertTrue(Arrays.asList("ecdsa-sha2-nistp256").containsAll(v.getKnownKeyTypes("h", 22)));
	}
}
