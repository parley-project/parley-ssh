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

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

import javax.crypto.SecretKey;

/**
 * ML-KEM-768 (FIPS 203) through the JDK's {@code javax.crypto.KEM}, which exists from Java 24.
 * The base level of this library is Java 11, so the KEM API is called by reflection and
 * {@link #isAvailable()} says whether the running JDK has it.
 * <p>
 * The wire values are the raw FIPS 203 encodings: the 1184 byte encapsulation key and the
 * 1088 byte ciphertext. The JDK wants the key as X.509 SubjectPublicKeyInfo, so the header is
 * added and removed here.
 *
 * @author Tony Bringardner
 */
final class MlKem768 {

	static final int PUBLIC_KEY_SIZE = 1184;
	static final int CIPHERTEXT_SIZE = 1088;
	static final int SECRET_SIZE = 32;

	/** SubjectPublicKeyInfo header for id-alg-ml-kem-768 (2.16.840.1.101.3.4.4.2) with a 1184 byte key */
	private static final byte[] X509_PREFIX = {0x30, (byte)0x82, 0x04, (byte)0xb2, 0x30, 0x0b, 0x06, 0x09, 0x60, (byte)0x86, 0x48,
			0x01, 0x65, 0x03, 0x04, 0x04, 0x02, 0x03, (byte)0x82, 0x04, (byte)0xa1, 0x00};

	private static final String ALG = "ML-KEM-768";
	private static final boolean AVAILABLE;
	private static Class<?> kemClass;
	private static Method getInstance, newEncapsulator, newDecapsulator, encapsulate, decapsulate, key, encapsulation;

	static {
		boolean ok = false;
		try {
			kemClass = Class.forName("javax.crypto.KEM");
			Class<?> encapsulator = Class.forName("javax.crypto.KEM$Encapsulator");
			Class<?> decapsulator = Class.forName("javax.crypto.KEM$Decapsulator");
			Class<?> encapsulated = Class.forName("javax.crypto.KEM$Encapsulated");
			getInstance = kemClass.getMethod("getInstance", String.class);
			newEncapsulator = kemClass.getMethod("newEncapsulator", PublicKey.class);
			newDecapsulator = kemClass.getMethod("newDecapsulator", java.security.PrivateKey.class);
			encapsulate = encapsulator.getMethod("encapsulate");
			decapsulate = decapsulator.getMethod("decapsulate", byte[].class);
			key = encapsulated.getMethod("key");
			encapsulation = encapsulated.getMethod("encapsulation");
			KeyPairGenerator.getInstance(ALG);
			getInstance.invoke(null, ALG);
			ok = true;
		} catch (Throwable e) {
			// Java before 24: not available
		}
		AVAILABLE = ok;
	}

	private KeyPair pair;

	static boolean isAvailable() {
		return AVAILABLE;
	}

	/**
	 * @return the 1184 byte encapsulation key
	 */
	byte[] generate(SecureRandom random) throws GeneralSecurityException {
		KeyPairGenerator g = KeyPairGenerator.getInstance(ALG);
		g.initialize(new java.security.spec.NamedParameterSpec(ALG), random);
		pair = g.generateKeyPair();
		byte[] enc = pair.getPublic().getEncoded();
		return Arrays.copyOfRange(enc, enc.length-PUBLIC_KEY_SIZE, enc.length);
	}

	/**
	 * Server side: make a shared secret for the peer's encapsulation key.
	 *
	 * @return {ciphertext, secret}
	 */
	static byte[][] encapsulate(byte[] publicKey, SecureRandom random) throws GeneralSecurityException {
		if( publicKey.length != PUBLIC_KEY_SIZE ) {
			throw new GeneralSecurityException("ML-KEM-768 public key of "+publicKey.length+" bytes");
		}
		byte[] enc = Arrays.copyOf(X509_PREFIX, X509_PREFIX.length+PUBLIC_KEY_SIZE);
		System.arraycopy(publicKey, 0, enc, X509_PREFIX.length, PUBLIC_KEY_SIZE);
		PublicKey pub = KeyFactory.getInstance(ALG).generatePublic(new X509EncodedKeySpec(enc));
		try {
			Object kem = getInstance.invoke(null, ALG);
			Object encapsulator = newEncapsulator.invoke(kem, pub);
			Object result = encapsulate.invoke(encapsulator);
			byte[] secret = ((SecretKey)key.invoke(result)).getEncoded();
			return new byte[][] {(byte[])encapsulation.invoke(result), secret};
		} catch (InvocationTargetException e) {
			throw asGeneral(e);
		} catch (ReflectiveOperationException e) {
			throw new GeneralSecurityException(e);
		}
	}

	/**
	 * Client side: recover the shared secret from the server's ciphertext.
	 */
	byte[] decapsulate(byte[] ciphertext) throws GeneralSecurityException {
		if( ciphertext.length != CIPHERTEXT_SIZE ) {
			throw new GeneralSecurityException("ML-KEM-768 ciphertext of "+ciphertext.length+" bytes");
		}
		try {
			Object kem = getInstance.invoke(null, ALG);
			Object decapsulator = newDecapsulator.invoke(kem, pair.getPrivate());
			return ((SecretKey)decapsulate.invoke(decapsulator, (Object)ciphertext)).getEncoded();
		} catch (InvocationTargetException e) {
			throw asGeneral(e);
		} catch (ReflectiveOperationException e) {
			throw new GeneralSecurityException(e);
		}
	}

	private static GeneralSecurityException asGeneral(InvocationTargetException e) {
		Throwable t = e.getCause();
		return t instanceof GeneralSecurityException ? (GeneralSecurityException)t : new GeneralSecurityException(t);
	}
}
