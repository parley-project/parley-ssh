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

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Arrays;

import us.bringardner.parley.ssh.SshBuffer;
import us.bringardner.parley.ssh.SshConstants;
import us.bringardner.parley.ssh.SshException;

/**
 * The post-quantum hybrid key exchange mlkem768x25519-sha256 (draft-ietf-sshm-mlkem-hybrid-kex,
 * OpenSSH 10's default): ML-KEM-768 and X25519 run together, so the session stays safe if
 * either one holds.
 * <p>
 * The client sends C_INIT = ML-KEM encapsulation key (1184 bytes) || X25519 public key (32),
 * message 30. The server encapsulates to the key, makes an X25519 key, and answers with its
 * host key, S_REPLY = ciphertext (1088) || X25519 public key (32) and its signature, message 31.
 * The shared secret is K = SHA-256(K_PQ || K_CL), and unlike the Diffie-Hellman methods it is
 * hashed and used to derive keys as a string, not an mpint ({@link #isSharedSecretString()}).
 *
 * @author Tony Bringardner
 */
public class MlKemX25519KeyExchange implements IKeyExchange {

	public static final String NAME = "mlkem768x25519-sha256";

	private static final int X25519_SIZE = 32;

	private IKexContext ctx;
	private MlKem768 mlkem;
	private X25519Agreement x25519;
	private byte[] clientValue;
	private byte[] h;
	private byte[] k;

	/**
	 * @return true if the running JDK has ML-KEM (Java 24 and later)
	 */
	public static boolean isSupported() {
		return MlKem768.isAvailable();
	}

	/**
	 * A factory for the catalog, which is only supported on a JDK that has ML-KEM.
	 */
	public static NamedFactory<IKeyExchange> factory() {
		return new NamedFactory<IKeyExchange>() {
			@Override
			public String getName() {
				return NAME;
			}

			@Override
			public IKeyExchange create() {
				return new MlKemX25519KeyExchange();
			}

			@Override
			public String toString() {
				return NAME;
			}

			@Override
			public boolean isSupported() {
				return MlKemX25519KeyExchange.isSupported();
			}
		};
	}

	@Override
	public String getName() {
		return NAME;
	}

	@Override
	public String getHashAlgorithm() {
		return "SHA-256";
	}

	@Override
	public boolean isSharedSecretString() {
		return true;
	}

	@Override
	public void start(IKexContext context) throws IOException {
		this.ctx = context;
		if( !isSupported() ) {
			throw new SshException(SshConstants.SSH_DISCONNECT_KEY_EXCHANGE_FAILED, NAME+" needs a JDK with ML-KEM (Java 24 or later)");
		}
		x25519 = new X25519Agreement();
		if( ctx.isClient() ) {
			try {
				mlkem = new MlKem768();
				byte[] pq = mlkem.generate(ctx.getRandom());
				byte[] cl = x25519.init(ctx.getRandom());
				clientValue = concat(pq, cl);
			} catch (GeneralSecurityException e) {
				throw failed(e);
			}
			ctx.send(SshBuffer.message(SshConstants.SSH_MSG_KEXDH_INIT).putString(clientValue));
		}
	}

	@Override
	public boolean handle(int msg, SshBuffer message) throws IOException {
		try {
			if( ctx.isClient() && msg == SshConstants.SSH_MSG_KEXDH_REPLY ) {
				byte[] hostKey = message.getString();
				byte[] serverValue = message.getString();
				byte[] signature = message.getString();
				if( serverValue.length != MlKem768.CIPHERTEXT_SIZE+X25519_SIZE ) {
					throw new SshException(SshConstants.SSH_DISCONNECT_KEY_EXCHANGE_FAILED, NAME+" server value of "+serverValue.length+" bytes");
				}
				byte[] kpq = mlkem.decapsulate(Arrays.copyOfRange(serverValue, 0, MlKem768.CIPHERTEXT_SIZE));
				byte[] kcl = x25519.agree(Arrays.copyOfRange(serverValue, MlKem768.CIPHERTEXT_SIZE, serverValue.length));
				k = secret(kpq, kcl);
				h = exchangeHash(hostKey, clientValue, serverValue);
				ctx.verifyHostKey(hostKey, signature, h);
				return true;
			}
			if( !ctx.isClient() && msg == SshConstants.SSH_MSG_KEXDH_INIT ) {
				clientValue = message.getString();
				if( clientValue.length != MlKem768.PUBLIC_KEY_SIZE+X25519_SIZE ) {
					throw new SshException(SshConstants.SSH_DISCONNECT_KEY_EXCHANGE_FAILED, NAME+" client value of "+clientValue.length+" bytes");
				}
				byte[][] enc = MlKem768.encapsulate(Arrays.copyOfRange(clientValue, 0, MlKem768.PUBLIC_KEY_SIZE), ctx.getRandom());
				byte[] cl = x25519.init(ctx.getRandom());
				byte[] kcl = x25519.agree(Arrays.copyOfRange(clientValue, MlKem768.PUBLIC_KEY_SIZE, clientValue.length));
				k = secret(enc[1], kcl);
				byte[] serverValue = concat(enc[0], cl);
				byte[] hostKey = ctx.getHostKey();
				h = exchangeHash(hostKey, clientValue, serverValue);
				byte[] signature = ctx.signExchangeHash(h);
				ctx.send(SshBuffer.message(SshConstants.SSH_MSG_KEXDH_REPLY)
						.putString(hostKey).putString(serverValue).putString(signature));
				return true;
			}
		} catch (GeneralSecurityException e) {
			throw failed(e);
		}
		throw new SshException("Unexpected "+SshConstants.messageName(msg)+" in "+NAME);
	}

	private static SshException failed(Exception e) {
		return new SshException(SshConstants.SSH_DISCONNECT_KEY_EXCHANGE_FAILED, NAME+": "+e.getMessage(), e);
	}

	private static byte[] concat(byte[] a, byte[] b) {
		byte[] ret = Arrays.copyOf(a, a.length+b.length);
		System.arraycopy(b, 0, ret, a.length, b.length);
		return ret;
	}

	private static byte[] secret(byte[] kpq, byte[] kcl) throws GeneralSecurityException {
		return MessageDigest.getInstance("SHA-256").digest(concat(kpq, kcl));
	}

	private byte[] exchangeHash(byte[] hostKey, byte[] clientValue, byte[] serverValue) throws GeneralSecurityException {
		SshBuffer b = new SshBuffer(4096);
		b.putString(ctx.getClientVersion());
		b.putString(ctx.getServerVersion());
		b.putString(ctx.getClientKexInit());
		b.putString(ctx.getServerKexInit());
		b.putString(hostKey);
		b.putString(clientValue);
		b.putString(serverValue);
		b.putString(k);
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		md.update(b.array(), b.readPosition(), b.available());
		return md.digest();
	}

	@Override
	public byte[] getExchangeHash() {
		return h;
	}

	@Override
	public byte[] getSharedSecret() {
		return k;
	}
}
