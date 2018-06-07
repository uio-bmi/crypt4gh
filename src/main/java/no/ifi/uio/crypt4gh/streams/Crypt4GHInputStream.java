package no.ifi.uio.crypt4gh.streams;

import htsjdk.samtools.seekablestream.SeekableStream;
import no.ifi.uio.crypt4gh.pojo.EncryptedHeader;
import no.ifi.uio.crypt4gh.pojo.Record;
import no.ifi.uio.crypt4gh.pojo.UnencryptedHeader;
import org.bouncycastle.jcajce.provider.util.BadBlockException;
import org.bouncycastle.openpgp.PGPException;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Arrays;

public class Crypt4GHInputStream extends SeekableStream {

    private final SeekableStream encryptedStream;
    private final long dataStart;
    private final SecretKeySpec secretKeySpec;
    private final byte[] initialIV;
    private final Cipher cipher;
    private final int blockSize;

    protected Crypt4GHInputStream(SeekableStream in, String key, String passphrase) throws IOException, PGPException, BadBlockException, NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, InvalidKeyException {
        encryptedStream = in;
        encryptedStream.seek(0);

        int unencryptedHeaderLength = 16;
        byte[] unencryptedHeaderBytes = new byte[unencryptedHeaderLength];
        encryptedStream.read(unencryptedHeaderBytes);
        UnencryptedHeader unencryptedHeader = new UnencryptedHeader(unencryptedHeaderBytes);
        int encryptedHeaderLength = unencryptedHeader.getFullHeaderLength() - unencryptedHeaderLength;
        byte[] encryptedHeaderBytes = new byte[encryptedHeaderLength];
        encryptedStream.read(encryptedHeaderBytes);
        EncryptedHeader encryptedHeader = new EncryptedHeader(encryptedHeaderBytes, key, passphrase);
        System.out.println("unencryptedHeader = " + unencryptedHeader);
        System.out.println("encryptedHeader = " + encryptedHeader);
        if (encryptedHeader.getRecords().size() != 1) {
            throw new BadBlockException("Only files encrypted with one single record are supported at the moment.", new RuntimeException());
        }

        Record record = encryptedHeader.getRecords().iterator().next();
        dataStart = unencryptedHeader.getFullHeaderLength() + record.getCiphertextStart();
        System.out.println("dataStart = " + dataStart);
        secretKeySpec = new SecretKeySpec(record.getKey(), 0, 32, record.getAlgorithm().getAlias().split("/")[0]);
        initialIV = Arrays.copyOf(record.getIv(), record.getIv().length);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(initialIV);
        cipher = Cipher.getInstance(record.getAlgorithm().getAlias());
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
        blockSize = cipher.getBlockSize();
    }

    @Override
    public long length() {
        return encryptedStream.length() - dataStart;
    }

    @Override
    public long position() throws IOException {
        return encryptedStream.position() - dataStart;
    }

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

    @Override
    public long skip(long n) throws IOException {
        seek(position() + n);
        return n;
    }

    @Override
    public int read() throws IOException {
        byte[] bytes = new byte[1];
        return read(bytes, 0, 1);
    }

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

    @Override
    public void close() throws IOException {
        encryptedStream.close();
    }

    @Override
    public boolean eof() throws IOException {
        return encryptedStream.eof();
    }

    @Override
    public String getSource() {
        return encryptedStream.getSource();
    }

}
