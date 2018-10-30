package no.ifi.uio.crypt4gh.stream;

import htsjdk.samtools.seekablestream.SeekableStream;
import no.ifi.uio.crypt4gh.factory.HeaderFactory;
import no.ifi.uio.crypt4gh.pojo.Header;
import no.ifi.uio.crypt4gh.pojo.Record;
import org.apache.commons.crypto.stream.PositionedCryptoInputStream;
import org.bouncycastle.jcajce.provider.util.BadBlockException;
import org.bouncycastle.openpgp.PGPException;

import java.io.IOException;
import java.util.Properties;

/**
 * <code>SeekableStream</code> wrapper to support Crypt4GH on-the-fly decryption.
 */
public class Crypt4GHInputStream extends SeekableStream {

    public static final int MINIMUM_BUFFER_SIZE = 512;

    private final SeekableStreamInput seekableStreamInput;
    private final PositionedCryptoInputStream encryptedStream;

    private final byte[] digest = new byte[32];

    /**
     * Constructor.
     *
     * @param in         Crypt4GH <code>SeekableStream</code> to be decrypted.
     * @param key        PGP private key.
     * @param passphrase PGP key passphrase.
     * @throws IOException       In case of IO error.
     * @throws PGPException      In case of decryption error.
     * @throws BadBlockException In case of decryption error.
     */
    public Crypt4GHInputStream(SeekableStream in, String key, char[] passphrase) throws IOException, PGPException, BadBlockException {
        this(in, key, passphrase, MINIMUM_BUFFER_SIZE);
    }

    /**
     * Constructor.
     *
     * @param in         Crypt4GH <code>SeekableStream</code> to be decrypted.
     * @param key        PGP private key.
     * @param passphrase PGP key passphrase.
     * @param bufferSize Size of the buffer to use, minimum 512.
     * @throws IOException       In case of IO error.
     * @throws PGPException      In case of decryption error.
     * @throws BadBlockException In case of decryption error.
     */
    public Crypt4GHInputStream(SeekableStream in, String key, char[] passphrase, int bufferSize) throws IOException, PGPException, BadBlockException {
        if (bufferSize < MINIMUM_BUFFER_SIZE) {
            throw new IOException("Minimum buffer size is " + MINIMUM_BUFFER_SIZE);
        }
        Header header = HeaderFactory.getInstance().getHeader(in, key, passphrase);
        Record record = header.getEncryptedHeader().getRecords().iterator().next();
        long ciphertextStart = record.getCiphertextStart();
        if (ciphertextStart != 0) { // Check if the file contains digest
            in.read(digest, 0, 32);
        }
        long dataStart = ciphertextStart + header.getUnencryptedHeader().getFullHeaderLength();
        this.seekableStreamInput = new SeekableStreamInput(in, bufferSize, dataStart);
        this.encryptedStream = new PositionedCryptoInputStream(new Properties(), seekableStreamInput, record.getKey(), record.getIv(), dataStart);
        seek(0);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public long length() {
        return this.seekableStreamInput.length();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public long position() throws IOException {
        return this.seekableStreamInput.position();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void seek(long position) throws IOException {
        this.encryptedStream.seek(position);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public int read() throws IOException {
        return this.encryptedStream.read();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public int read(byte[] buffer, int offset, int length) throws IOException {
        return this.encryptedStream.read(buffer, offset, length);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void close() throws IOException {
        this.encryptedStream.close();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean eof() throws IOException {
        return this.seekableStreamInput.eof();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String getSource() {
        return this.seekableStreamInput.getSource();
    }

    /**
     * Utility method to get SHA256 digest of the raw data.
     *
     * @return SHA256 digest of the raw data.
     */
    public byte[] getDigest() {
        return digest;
    }

}
