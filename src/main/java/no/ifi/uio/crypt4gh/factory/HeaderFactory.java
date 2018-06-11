package no.ifi.uio.crypt4gh.factory;

import no.ifi.uio.crypt4gh.pojo.*;
import org.bouncycastle.jcajce.provider.util.BadBlockException;
import org.bouncycastle.openpgp.PGPException;
import org.c02e.jpgpj.Decryptor;
import org.c02e.jpgpj.Key;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class HeaderFactory {

    public static int UNENCRYPTED_HEADER_LENGTH = 16;

    private static volatile HeaderFactory INSTANCE;

    public static HeaderFactory getInstance() {
        if (INSTANCE == null) {
            synchronized (HeaderFactory.class) {
                if (INSTANCE == null) {
                    INSTANCE = new HeaderFactory();
                }
            }
        }
        return INSTANCE;
    }

    private HeaderFactory() {
    }

    public Header getHeader(byte[] headerBytes, String key, String passphrase) throws PGPException, IOException, BadBlockException {
        return getHeader(new ByteArrayInputStream(headerBytes), key, passphrase);
    }

    public Header getHeader(InputStream in, String key, String passphrase) throws IOException, PGPException, BadBlockException {
        UnencryptedHeader unencryptedHeader = getUnencryptedHeader(in);
        return new Header(unencryptedHeader, getEncryptedHeader(in, unencryptedHeader, key, passphrase));
    }

    protected UnencryptedHeader getUnencryptedHeader(InputStream in) throws IOException {
        byte[] unencryptedHeaderBytes = new byte[UNENCRYPTED_HEADER_LENGTH];
        in.read(unencryptedHeaderBytes);
        String protocolName = new String(Arrays.copyOfRange(unencryptedHeaderBytes, 0, 8));
        int version = getInt(Arrays.copyOfRange(unencryptedHeaderBytes, 8, 12));
        int fullHeaderLength = getInt(Arrays.copyOfRange(unencryptedHeaderBytes, 12, 16));
        return new UnencryptedHeader(protocolName, version, fullHeaderLength);
    }

    protected EncryptedHeader getEncryptedHeader(InputStream in, UnencryptedHeader unencryptedHeader, String key, String passphrase) throws IOException, PGPException, BadBlockException {
        int encryptedHeaderLength = unencryptedHeader.getFullHeaderLength() - UNENCRYPTED_HEADER_LENGTH;
        byte[] encryptedHeaderBytes = new byte[encryptedHeaderLength];
        in.read(encryptedHeaderBytes);
        Decryptor decryptor = new Decryptor(new Key(key, passphrase));
        decryptor.setVerificationRequired(false);
        ByteArrayOutputStream decryptedHeaderStream = new ByteArrayOutputStream();
        decryptor.decrypt(new ByteArrayInputStream(encryptedHeaderBytes), decryptedHeaderStream);
        byte[] decryptedHeader = decryptedHeaderStream.toByteArray();
        long numberOfRecords = getInt(Arrays.copyOfRange(decryptedHeader, 0, 4));
        List<Record> records = new ArrayList<>();
        for (int i = 0; i < numberOfRecords; i++) {
            records.add(getRecord(Arrays.copyOfRange(decryptedHeader, 4 + 84 * i, 4 + 84 * (i + 1))));
        }
        EncryptedHeader encryptedHeader = new EncryptedHeader(numberOfRecords, records);
        if (encryptedHeader.getRecords().size() != 1) {
            throw new BadBlockException("Only files encrypted with one single record are supported at the moment.", new RuntimeException());
        }
        return encryptedHeader;
    }

    protected Record getRecord(byte[] recordBytes) {
        long plaintextStart = getLong(Arrays.copyOfRange(recordBytes, 0, 8));
        long plaintextEnd = getLong(Arrays.copyOfRange(recordBytes, 8, 16));
        long ciphertextStart = getLong(Arrays.copyOfRange(recordBytes, 16, 24));
        long ciphertextEnd = getLong(Arrays.copyOfRange(recordBytes, 24, 32));
        int method = getInt(Arrays.copyOfRange(recordBytes, 32, 36));
        EncryptionAlgorithm algorithm = EncryptionAlgorithm.valueOf(method);
        byte[] key = Arrays.copyOfRange(recordBytes, 36, 68);
        byte[] iv = Arrays.copyOfRange(recordBytes, 68, 84);
        return new Record(plaintextStart, plaintextEnd, ciphertextStart, ciphertextEnd, algorithm, key, iv);
    }

    protected int getInt(byte[] bytes) {
        return ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN).getInt();
    }

    protected long getLong(byte[] bytes) {
        return ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN).getLong();
    }

}
