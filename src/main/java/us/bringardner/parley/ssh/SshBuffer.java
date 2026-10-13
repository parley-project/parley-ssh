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
package us.bringardner.parley.ssh;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import us.bringardner.parley.io.WireBuffer;
import us.bringardner.parley.io.WireFormatException;

/**
 * Reads and writes the SSH data types (RFC 4251 section 5): byte, boolean, uint32, uint64,
 * string, mpint and name-list.
 * <p>
 * Writing appends at the end and grows the buffer; reading takes from the front. A read past
 * the end, or a string longer than what is left, throws an SshException (a protocol error),
 * so a malformed packet can't make the reader allocate a huge array.
 * <p>
 * The bytes are kept by parley-io's {@link WireBuffer}, which DNS messages use too; this
 * class adds the SSH types and turns malformed data into an SshException.
 * Not thread safe.
 *
 * @author Tony Bringardner
 */
public final class SshBuffer {

	private final WireBuffer buf;

	/**
	 * An empty buffer for writing.
	 */
	public SshBuffer() {
		this(256);
	}

	public SshBuffer(int capacity) {
		buf = new WireBuffer(Math.max(16, capacity));
	}

	/**
	 * A buffer for reading data (not copied).
	 */
	public SshBuffer(byte[] data) {
		this(data, 0, data.length);
	}

	/**
	 * A buffer for reading data[off..off+len) (not copied).
	 */
	public SshBuffer(byte[] data, int off, int len) {
		buf = new WireBuffer(data, off, len);
	}

	private SshBuffer(WireBuffer buf) {
		this.buf = buf;
	}

	/**
	 * A buffer for reading the bytes from position to limit (copied if not array backed).
	 */
	public static SshBuffer wrap(ByteBuffer in) {
		return new SshBuffer(WireBuffer.wrap(in));
	}

	/**
	 * @return a buffer for writing that starts with the message number
	 */
	public static SshBuffer message(int msg) {
		SshBuffer ret = new SshBuffer();
		ret.putByte(msg);
		return ret;
	}

	// ------------------------------------------------------------------ state

	/**
	 * @return bytes left to read
	 */
	public int available() {
		return buf.remaining();
	}

	public int readPosition() {
		return buf.readPosition();
	}

	public void readPosition(int pos) {
		if( pos < 0 || pos > buf.writePosition() ) {
			throw new IllegalArgumentException("position "+pos);
		}
		buf.readPosition(pos);
	}

	public int writePosition() {
		return buf.writePosition();
	}

	/**
	 * @return the backing array (the data is from readPosition() to writePosition())
	 */
	public byte[] array() {
		return buf.array();
	}

	/**
	 * @return a copy of the unread bytes
	 */
	public byte[] toByteArray() {
		return buf.toByteArray();
	}

	/**
	 * @return the unread bytes as a ByteBuffer (shares the array)
	 */
	public ByteBuffer toByteBuffer() {
		return buf.toByteBuffer();
	}

	// ------------------------------------------------------------------ writing

	public SshBuffer putByte(int b) {
		buf.putU8(b);
		return this;
	}

	public SshBuffer putBoolean(boolean b) {
		return putByte(b ? 1 : 0);
	}

	/**
	 * uint32 (the low 32 bits of the value)
	 */
	public SshBuffer putInt(long v) {
		buf.putU32(v);
		return this;
	}

	/**
	 * uint64
	 */
	public SshBuffer putLong(long v) {
		buf.putInt64(v);
		return this;
	}

	/**
	 * Raw bytes, no length.
	 */
	public SshBuffer putRaw(byte[] b) {
		return putRaw(b, 0, b.length);
	}

	public SshBuffer putRaw(byte[] b, int off, int len) {
		buf.putBytes(b, off, len);
		return this;
	}

	/**
	 * string: uint32 length then the bytes.
	 */
	public SshBuffer putString(byte[] b) {
		return putString(b, 0, b.length);
	}

	public SshBuffer putString(byte[] b, int off, int len) {
		buf.putBytes32(b, off, len);
		return this;
	}

	/**
	 * string, UTF-8 encoded.
	 */
	public SshBuffer putString(String s) {
		return putString(s.getBytes(StandardCharsets.UTF_8));
	}

	/**
	 * mpint: two's complement, big endian, the fewest bytes; zero is the empty string.
	 */
	public SshBuffer putMpint(BigInteger v) {
		if( v.signum() == 0 ) {
			return putInt(0);
		}
		return putString(v.toByteArray());
	}

	/**
	 * mpint of a non-negative number given as unsigned big endian bytes (e.g. a shared secret).
	 */
	public SshBuffer putMpint(byte[] unsigned) {
		return putMpint(new BigInteger(1, unsigned));
	}

	/**
	 * name-list: the names joined with commas, as a string.
	 */
	public SshBuffer putNameList(List<String> names) {
		return putString(String.join(",", names));
	}

	/**
	 * The unread bytes of another buffer.
	 */
	public SshBuffer putBuffer(SshBuffer other) {
		return putRaw(other.array(), other.readPosition(), other.available());
	}

	// ------------------------------------------------------------------ reading

	private static SshException malformed(WireFormatException e) {
		return new SshException("Malformed packet: "+e.getMessage());
	}

	public int getByte() throws SshException {
		try {
			return buf.getU8();
		} catch (WireFormatException e) {
			throw malformed(e);
		}
	}

	public boolean getBoolean() throws SshException {
		return getByte() != 0;
	}

	/**
	 * uint32 as a long (0 to 2^32-1).
	 */
	public long getUInt() throws SshException {
		try {
			return buf.getU32();
		} catch (WireFormatException e) {
			throw malformed(e);
		}
	}

	/**
	 * uint32 that must fit an int (0 to 2^31-1), e.g. a length or a channel number.
	 */
	public int getInt() throws SshException {
		long ret = getUInt();
		if( ret > Integer.MAX_VALUE ) {
			throw new SshException("Malformed packet: value "+ret+" is too large");
		}
		return (int) ret;
	}

	public long getLong() throws SshException {
		try {
			return buf.getInt64();
		} catch (WireFormatException e) {
			throw malformed(e);
		}
	}

	public byte[] getRaw(int len) throws SshException {
		try {
			return buf.getBytes(len);
		} catch (WireFormatException e) {
			throw malformed(e);
		}
	}

	/**
	 * string as bytes; the length is checked against what is left before anything is allocated.
	 */
	public byte[] getString() throws SshException {
		try {
			return buf.getBytes32();
		} catch (WireFormatException e) {
			throw malformed(e);
		}
	}

	/**
	 * string decoded as UTF-8.
	 */
	public String getStringUtf8() throws SshException {
		return new String(getString(), StandardCharsets.UTF_8);
	}

	public BigInteger getMpint() throws SshException {
		byte[] b = getString();
		return b.length == 0 ? BigInteger.ZERO : new BigInteger(b);
	}

	public List<String> getNameList() throws SshException {
		String s = new String(getString(), StandardCharsets.US_ASCII);
		if( s.isEmpty() ) {
			return Collections.emptyList();
		}
		List<String> ret = new ArrayList<String>();
		for (String name : s.split(",", -1)) {
			if( name.isEmpty() ) {
				throw new SshException("Malformed name-list: '"+s+"'");
			}
			ret.add(name);
		}
		return ret;
	}

	/**
	 * Skip len bytes.
	 */
	public void skip(int len) throws SshException {
		try {
			buf.skip(len);
		} catch (WireFormatException e) {
			throw malformed(e);
		}
	}

	@Override
	public String toString() {
		return "SshBuffer[read="+buf.readPosition()+", write="+buf.writePosition()+", capacity="+buf.array().length+"]";
	}
}
