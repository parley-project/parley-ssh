/**
 * <PRE>
 * 
 * Copyright Tony Bringardner 1998, 2026 <A href="http://bringardner.com/tony">Tony Bringardner</A>
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
package us.bringardner.parley.ssh.algorithms;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.security.SecureRandom;

import org.junit.jupiter.api.Test;

/**
 * The ML-KEM-768 wrapper and the hybrid method's place in the catalog. The whole exchange
 * runs against the server in ServerTest.everyAlgorithm.
 */
public class MlKemKeyExchangeTest {

	@Test
	public void encapsulationAgrees() throws Exception {
		assumeTrue(MlKemX25519KeyExchange.isSupported(), "needs Java 24+");
		SecureRandom r = new SecureRandom();
		MlKem768 client = new MlKem768();
		byte[] pub = client.generate(r);
		assertEquals(MlKem768.PUBLIC_KEY_SIZE, pub.length);
		byte[][] enc = MlKem768.encapsulate(pub, r);
		assertEquals(MlKem768.CIPHERTEXT_SIZE, enc[0].length);
		assertEquals(MlKem768.SECRET_SIZE, enc[1].length);
		assertArrayEquals(enc[1], client.decapsulate(enc[0]));
	}

	@Test
	public void offeredFirstOnlyWhenTheJdkHasIt() {
		boolean offered = SshAlgorithms.defaults().getKeyExchangeNames().contains(MlKemX25519KeyExchange.NAME);
		assertEquals(MlKemX25519KeyExchange.isSupported(), offered);
		if( offered ) {
			assertEquals(MlKemX25519KeyExchange.NAME, SshAlgorithms.defaults().getKeyExchangeNames().get(0));
			assertTrue(new MlKemX25519KeyExchange().isSharedSecretString());
		}
		assertFalse(new EphemeralKeyExchange("x", "SHA-256", X25519Agreement::new).isSharedSecretString());
	}
}
