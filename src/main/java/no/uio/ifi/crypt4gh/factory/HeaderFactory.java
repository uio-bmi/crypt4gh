package no.uio.ifi.crypt4gh.factory;

import no.uio.ifi.crypt4gh.pojo.*;
import org.bouncycastle.jcajce.provider.util.BadBlockException;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.c02e.jpgpj.Decryptor;
import org.c02e.jpgpj.Key;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.*;

/**
 * Factory for extracting Crypt4GH headers from input streams.
 */
public class HeaderFactory {

    public static int UNENCRYPTED_HEADER_LENGTH = 16;

    private static volatile HeaderFactory INSTANCE;

    /**
     * As it's singleton, this is the method for obtaining its instance.
     *
     * @return <code>HeaderFactory</code> instance.
     */
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

    /**
     * Private ctor.
     */
    private HeaderFactory() {
    }

    /**
     * Obtains PGP Key IDs from Crypt4GH header.
     *
     * @param headerBytes Header bytes.
     * @return Collection of PGP Key IDs.
     * @throws IOException  In case of IO error.
     * @throws PGPException In case of PGP error.
     */
    public Collection<String> getKeyIds(byte[] headerBytes) throws IOException, PGPException {
        ByteArrayInputStream headerInputStream = new ByteArrayInputStream(headerBytes);
        getUnencryptedHeader(headerInputStream);
        InputStream decoderStream = PGPUtil.getDecoderStream(headerInputStream);
        PGPObjectFactory pgpObjectFactory = new PGPObjectFactory(decoderStream, new BcKeyFingerprintCalculator());
        PGPEncryptedDataList pgpEncryptedDataList = (PGPEncryptedDataList) pgpObjectFactory.nextObject();
        Iterator iterator = pgpEncryptedDataList.getEncryptedDataObjects();
        Set<String> ids = new HashSet<>();
        while (iterator.hasNext()) {
            Object entry = iterator.next();
            PGPPublicKeyEncryptedData pgpPublicKeyEncryptedData = (PGPPublicKeyEncryptedData) entry;
            ids.add(Long.toHexString(pgpPublicKeyEncryptedData.getKeyID()));
        }
        if (ids.isEmpty()) {
            throw new PGPException("KeyID not found in the encrypted part of the header.");
        } else {
            return ids;
        }
    }

    /**
     * Constructs header based on header bytes, PGP key and PGP key passphrase.
     *
     * @param headerBytes Header bytes.
     * @param key         PGP private key.
     * @param passphrase  PGP key passphrase.
     * @return Header POJO.
     * @throws PGPException      In case of PGP error.
     * @throws IOException       In case of IO error.
     * @throws BadBlockException In case of decryption error.
     */
    public Header getHeader(byte[] headerBytes, String key, char[] passphrase) throws PGPException, IOException, BadBlockException {
        return getHeader(new ByteArrayInputStream(headerBytes), key, passphrase);
    }

    /**
     * Extracts header from an InputStream, having PGP key and PGP key passphrase.
     *
     * @param in         InputStream to retrieve header from.
     * @param key        PGP private key.
     * @param passphrase PGP key passphrase.
     * @return Header POJO.
     * @throws PGPException      In case of PGP error.
     * @throws IOException       In case of IO error.
     * @throws BadBlockException In case of decryption error.
     */
    public Header getHeader(InputStream in, String key, char[] passphrase) throws IOException, PGPException, BadBlockException {
        UnencryptedHeader unencryptedHeader = getUnencryptedHeader(in);
        return new Header(unencryptedHeader, getEncryptedHeader(in, unencryptedHeader, key, passphrase));
    }

    /**
     * Extracts unencrypted header from an InputStream.
     *
     * @param in InputStream to retrieve header from.
     * @return Unencrypted header POJO.
     * @throws IOException In case of IO error.
     */
    protected UnencryptedHeader getUnencryptedHeader(InputStream in) throws IOException {
        byte[] unencryptedHeaderBytes = new byte[UNENCRYPTED_HEADER_LENGTH];
        in.read(unencryptedHeaderBytes);
        String protocolName = new String(Arrays.copyOfRange(unencryptedHeaderBytes, 0, 8));
        int version = getInt(Arrays.copyOfRange(unencryptedHeaderBytes, 8, 12));
        int fullHeaderLength = getInt(Arrays.copyOfRange(unencryptedHeaderBytes, 12, 16));
        return new UnencryptedHeader(protocolName, version, fullHeaderLength);
    }

    /**
     * Extracts encrypted header from an InputStream.
     *
     * @param in                InputStream to retrieve header from.
     * @param unencryptedHeader Unencrypted header POJO.
     * @param key               ASCII-armored locked PGP private key.
     * @param passphrase        PGP key passphrase.
     * @return Encrypted header POJO.
     * @throws PGPException      In case of PGP error.
     * @throws IOException       In case of IO error.
     * @throws BadBlockException In case of decryption error.
     */
    protected EncryptedHeader getEncryptedHeader(InputStream in, UnencryptedHeader unencryptedHeader, String key, char[] passphrase) throws IOException, PGPException, BadBlockException {
        return getEncryptedHeader(in, unencryptedHeader, new Key(key, passphrase));
    }

    /**
     * Extracts encrypted header from an InputStream.
     *
     * @param in                InputStream to retrieve header from.
     * @param unencryptedHeader Unencrypted header POJO.
     * @param key               PGP private key.
     * @return Encrypted header POJO.
     * @throws PGPException      In case of PGP error.
     * @throws IOException       In case of IO error.
     * @throws BadBlockException In case of decryption error.
     */
    protected EncryptedHeader getEncryptedHeader(InputStream in, UnencryptedHeader unencryptedHeader, Key key) throws IOException, PGPException, BadBlockException {
        int encryptedHeaderLength = unencryptedHeader.getFullHeaderLength() - UNENCRYPTED_HEADER_LENGTH;
        byte[] encryptedHeaderBytes = new byte[encryptedHeaderLength];
        in.read(encryptedHeaderBytes);
        Decryptor decryptor = new Decryptor(key);
        decryptor.setVerificationRequired(false);
        ByteArrayOutputStream decryptedHeaderStream = new ByteArrayOutputStream();
        decryptor.decrypt(new ByteArrayInputStream(encryptedHeaderBytes), decryptedHeaderStream);
        decryptor.clearSecrets();
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

    /**
     * Constructs Record (i.e. Encryption Parameters) from record bytes.
     *
     * @param recordBytes Record bytes.
     * @return Record POJO.
     */
    protected Record getRecord(byte[] recordBytes) {
        long plaintextStart = getLong(Arrays.copyOfRange(recordBytes, 0, 8));
        long plaintextEnd = getLong(Arrays.copyOfRange(recordBytes, 8, 16));
        long ciphertextStart = getLong(Arrays.copyOfRange(recordBytes, 16, 24));
        long ctrOffset = getLong(Arrays.copyOfRange(recordBytes, 24, 32));
        int method = getInt(Arrays.copyOfRange(recordBytes, 32, 36));
        EncryptionAlgorithm algorithm = EncryptionAlgorithm.valueOf(method);
        byte[] key = Arrays.copyOfRange(recordBytes, 36, 68);
        byte[] iv = Arrays.copyOfRange(recordBytes, 68, 84);
        return new Record(plaintextStart, plaintextEnd, ciphertextStart, ctrOffset, algorithm, key, iv);
    }

    /**
     * Utility method to get little endian integer from byte array.
     *
     * @param bytes Byte array.
     * @return Integer.
     */
    protected int getInt(byte[] bytes) {
        return ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN).getInt();
    }

    /**
     * Utility method to get little endian long from byte array.
     *
     * @param bytes Byte array.
     * @return Long.
     */
    protected long getLong(byte[] bytes) {
        return ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN).getLong();
    }

}
