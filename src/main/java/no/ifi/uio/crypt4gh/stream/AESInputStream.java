package no.ifi.uio.crypt4gh.stream;

import htsjdk.samtools.seekablestream.SeekableStream;
import no.ifi.uio.crypt4gh.pojo.EncryptionAlgorithm;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;

/**
 * SeekableStream wrapper to support AES on-the-fly decryption.
 */
public class AESInputStream extends SeekableStream {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private final SeekableStream encryptedStream;
    private final long dataStart;
    private final SecretKeySpec secretKeySpec;
    private final byte[] initialIV;
    private final Cipher cipher;
    private final int blockSize;

    /**
     * Constructor without data start (default = 0).
     *
     * @param in        AES256 <code>SeekableStream</code> to be decrypted.
     * @param key       AES key.
     * @param initialIV AES initial IV.
     * @throws IOException                        In case of IO error.
     * @throws NoSuchPaddingException             In case of decryption error.
     * @throws NoSuchAlgorithmException           In case of decryption error.
     * @throws InvalidAlgorithmParameterException In case of decryption error.
     * @throws InvalidKeyException                In case of decryption error.
     * @throws NoSuchProviderException            In case of decryption error.
     */
    public AESInputStream(SeekableStream in, byte[] key, byte[] initialIV) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, NoSuchProviderException {
        this(in, key, initialIV, 0);
    }

    /**
     * Constructor with data start.
     *
     * @param in        AES256 <code>SeekableStream</code> to be decrypted.
     * @param key       AES key.
     * @param initialIV AES initial IV.
     * @param dataStart Start position of the data in the stream.
     * @throws IOException                        In case of IO error.
     * @throws NoSuchPaddingException             In case of decryption error.
     * @throws NoSuchAlgorithmException           In case of decryption error.
     * @throws InvalidAlgorithmParameterException In case of decryption error.
     * @throws InvalidKeyException                In case of decryption error.
     * @throws NoSuchProviderException            In case of decryption error.
     */
    public AESInputStream(SeekableStream in, byte[] key, byte[] initialIV, long dataStart) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, NoSuchProviderException {
        this.encryptedStream = in;
        this.dataStart = dataStart;
        this.secretKeySpec = new SecretKeySpec(key, EncryptionAlgorithm.AES_256_CTR.getAlias().split("/")[0]);
        this.initialIV = initialIV;
        this.cipher = Cipher.getInstance(EncryptionAlgorithm.AES_256_CTR.getAlias(), BouncyCastleProvider.PROVIDER_NAME);
        this.cipher.init(Cipher.DECRYPT_MODE, this.secretKeySpec, new IvParameterSpec(this.initialIV));
        this.blockSize = cipher.getBlockSize();
        seek(0);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public long length() {
        return encryptedStream.length() - dataStart;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public long position() throws IOException {
        return encryptedStream.position() - dataStart;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void seek(long position) throws IOException {
        encryptedStream.seek(position + dataStart);

        long block = position / blockSize;

        // Update CTR IV counter according to block number
        BigInteger ivBI = new BigInteger(initialIV);
        ivBI = ivBI.add(BigInteger.valueOf(block));
        IvParameterSpec newIVParameterSpec = new IvParameterSpec(ivBI.toByteArray());

        try {
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, newIVParameterSpec);
        } catch (Exception e) {
            throw new IOException(e);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public long skip(long n) throws IOException {
        seek(position() + n);
        return n;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public int read() throws IOException {
        byte[] bytes = new byte[1];
        return read(bytes, 0, 1);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public int read(byte[] buffer, int offset, int length) throws IOException {
        if (eof()) {
            return -1;
        }
        long currentPosition = position();
        long startBlock = currentPosition / blockSize;
        long start = startBlock * blockSize;
        long endBlock = (currentPosition + length) / blockSize + 1;
        long end = endBlock * blockSize;
        if (end > length()) {
            end = length();
        }
        if (length > end - start) {
            length = (int) (end - start);
        }
        int prepended = (int) (currentPosition - start);
        int appended = (int) (end - (currentPosition + length));
        encryptedStream.seek(start + dataStart);
        int total = prepended + length + appended;
        byte[] encryptedBytes = new byte[total];
        encryptedStream.read(encryptedBytes, offset, total);
        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(encryptedBytes);
        CipherInputStream cipherInputStream = new CipherInputStream(byteArrayInputStream, cipher);
        cipherInputStream.read(new byte[prepended]);
        int realRead = 0;
        int read;
        while (length != 0 && (read = cipherInputStream.read(buffer, offset, length)) != -1) {
            offset += read;
            length -= read;
            realRead += read;
        }
        encryptedStream.seek(currentPosition + realRead + dataStart);
        return realRead;
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
