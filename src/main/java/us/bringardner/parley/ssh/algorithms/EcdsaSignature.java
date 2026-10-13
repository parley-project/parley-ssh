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

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;

import us.bringardner.parley.core.util.Ec;
import us.bringardner.parley.ssh.SshBuffer;
import us.bringardner.parley.ssh.SshException;

/**
 * ecdsa-sha2-nistp256, -nistp384 and -nistp521 (RFC 5656 3.1.2). The SSH signature is
 * string(mpint r, mpint s); Java's is DER, so this converts between them.
 *
 * @author Tony Bringardner
 */
public class EcdsaSignature implements ISignatureAlgorithm {

	private final String name;
	private final String curve;
	private final String jceName;

	/**
	 * @param curve nistp256, nistp384 or nistp521
	 * @param jceName SHA256withECDSA, SHA384withECDSA or SHA512withECDSA
	 */
	public EcdsaSignature(String curve, String jceName) {
		this.name = "ecdsa-sha2-"+curve;
		this.curve = curve;
		this.jceName = jceName;
	}

	@Override
	public String getName() {
		return name;
	}

	@Override
	public String getKeyType() {
		return name;
	}

	@Override
	public boolean verify(PublicKey key, byte[] data, byte[] signature) throws SshException {
		if( !(key instanceof ECPublicKey) || !curve.equals(SshPublicKeys.curveName(((ECPublicKey) key).getParams())) ) {
			return false;
		}
		SshBuffer b = new SshBuffer(signature);
		if( !name.equals(b.getStringUtf8()) ) {
			return false;
		}
		SshBuffer rs = new SshBuffer(b.getString());
		BigInteger r = rs.getMpint();
		BigInteger s = rs.getMpint();
		if( r.signum() <= 0 || s.signum() <= 0 ) {
			return false;
		}
		try {
			Signature sig = Signature.getInstance(jceName);
			sig.initVerify(key);
			sig.update(data);
			return sig.verify(toDer(r, s));
		} catch (GeneralSecurityException e) {
			return false;
		}
	}

	@Override
	public byte[] sign(PrivateKey key, byte[] data) throws GeneralSecurityException {
		Signature sig = Signature.getInstance(jceName);
		sig.initSign(key);
		sig.update(data);
		BigInteger[] rs = fromDer(sig.sign());
		byte[] inner = new SshBuffer().putMpint(rs[0]).putMpint(rs[1]).toByteArray();
		return new SshBuffer().putString(name).putString(inner).toByteArray();
	}

	@Override
	public String toString() {
		return name;
	}

	// ------------------------------------------------------------------ DER SEQUENCE { INTEGER r, INTEGER s }

	/** @see Ec#signatureToDer(BigInteger, BigInteger) */
	static byte[] toDer(BigInteger r, BigInteger s) {
		return Ec.signatureToDer(r, s);
	}

	/** @see Ec#signatureFromDer(byte[]) */
	static BigInteger[] fromDer(byte[] der) throws GeneralSecurityException {
		return Ec.signatureFromDer(der);
	}
}
