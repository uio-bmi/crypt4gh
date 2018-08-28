package no.ifi.uio.crypt4gh.stream;

import htsjdk.samtools.seekablestream.SeekableStream;
import no.ifi.uio.crypt4gh.factory.HeaderFactory;
import no.ifi.uio.crypt4gh.pojo.Header;
import no.ifi.uio.crypt4gh.pojo.Record;
import org.bouncycastle.jcajce.provider.util.BadBlockException;
import org.bouncycastle.openpgp.PGPException;

import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

/**
 * SeekableStream wrapper to support Crypt4GH on-the-fly decryption.
 */
public class Crypt4GHInputStream extends SeekableStream {

    private final SeekableStream encryptedStream;

    private final byte[] digest = new byte[32];

    /**
     * Constructor.
     *
     * @param in         Crypt4GH <code>SeekableStream</code> to be decrypted.
     * @param key        PGP private key.
     * @param passphrase PGP key passphrase.
     * @throws IOException                        In case of IO error.
     * @throws NoSuchPaddingException             In case of decryption error.
     * @throws NoSuchAlgorithmException           In case of decryption error.
     * @throws InvalidAlgorithmParameterException In case of decryption error.
     * @throws InvalidKeyException                In case of decryption error.
     * @throws NoSuchProviderException            In case of decryption error.
     * @throws PGPException                       In case of decryption error.
     * @throws BadBlockException                  In case of decryption error.
     */
    public Crypt4GHInputStream(SeekableStream in, String key, String passphrase) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, NoSuchProviderException, PGPException, BadBlockException {
        Header header = HeaderFactory.getInstance().getHeader(in, key, passphrase);
        Record record = header.getEncryptedHeader().getRecords().iterator().next();
        BigInteger iv = new BigInteger(record.getIv());
        iv = iv.add(BigInteger.valueOf(record.getCtrOffset()));
        byte[] initialIV = iv.toByteArray();
        in.read(digest, 0, 32);
        this.encryptedStream = new AESInputStream(in, record.getKey(), initialIV, header.getDataStart());
        seek(0);
    }

    /**
     * Utility method to get SHA256 digest of the raw data.
     *
     * @return SHA256 digest of the raw data.
     */
    public byte[] getDigest() {
        return digest;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public long length() {
        return encryptedStream.length();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public long position() throws IOException {
        return encryptedStream.position();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void seek(long position) throws IOException {
        encryptedStream.seek(position);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public int read() throws IOException {
        return encryptedStream.read();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public int read(byte[] buffer, int offset, int length) throws IOException {
        return encryptedStream.read(buffer, offset, length);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void close() throws IOException {
        encryptedStream.close();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean eof() throws IOException {
        return encryptedStream.eof();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String getSource() {
        return encryptedStream.getSource();
    }

}
