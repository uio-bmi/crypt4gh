package no.ifi.uio.crypt4gh.stream;

import no.ifi.uio.crypt4gh.factory.HeaderFactory;
import no.ifi.uio.crypt4gh.pojo.EncryptionAlgorithm;
import org.apache.commons.crypto.stream.CryptoOutputStream;
import org.bouncycastle.openpgp.PGPException;
import org.c02e.jpgpj.Encryptor;
import org.c02e.jpgpj.HashingAlgorithm;
import org.c02e.jpgpj.Key;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Properties;

/**
 * OutputStream wrapper to support Crypt4GH on-the-fly encryption.
 */
public class Crypt4GHOutputStream extends FilterOutputStream {

    public static final String PROTOCOL_NAME = "crypt4gh";
    public static final int VERSION = 1;
    public static final int KEY_LENGTH = 256;
    public static final int IV_LENGTH = 16;
    public static final int NUMBER_OF_RECORDS = 1;
    public static final long PLAINTEXT_START = 0;
    public static final long PLAINTEXT_END = 0xFFFFFFFF;
    public static final long CIPHERTEXT_START = 0;
    public static final long CTR_OFFSET = 0;

    /**
     * Constructor that wraps OutputStream.
     *
     * @param out OutputStream to encrypt.
     * @param key PGP public key.
     * @throws IOException              In case of IO error.
     * @throws PGPException             In case of PGP error.
     * @throws NoSuchAlgorithmException In case of decryption error.
     */
    public Crypt4GHOutputStream(OutputStream out, String key) throws IOException, NoSuchAlgorithmException, PGPException {
        this(out, key, null);
    }

    /**
     * Constructor that wraps OutputStream and adds SHA256 digest to it.
     *
     * @param out    OutputStream to encrypt.
     * @param key    PGP public key.
     * @param digest SHA256 digest
     * @throws IOException              In case of IO error.
     * @throws PGPException             In case of PGP error.
     * @throws NoSuchAlgorithmException In case of decryption error.
     */
    public Crypt4GHOutputStream(OutputStream out, String key, byte[] digest) throws IOException, NoSuchAlgorithmException, PGPException {
        super(out);

        SecureRandom secureRandom = new SecureRandom();
        String alias = EncryptionAlgorithm.AES_256_CTR.getAlias();
        KeyGenerator keyGenerator = KeyGenerator.getInstance(alias.split("/")[0]);
        keyGenerator.init(KEY_LENGTH, secureRandom);
        SecretKey sessionKey = keyGenerator.generateKey();
        byte[] ivBytes = new byte[IV_LENGTH];
        secureRandom.nextBytes(ivBytes);

        long ciphertextStart = CIPHERTEXT_START;
        if (digest != null) {
            ciphertextStart = digest.length;
        }

        ByteArrayOutputStream decryptedHeaderOutputStream = new ByteArrayOutputStream();
        decryptedHeaderOutputStream.write(ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(NUMBER_OF_RECORDS).array());
        decryptedHeaderOutputStream.write(ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putLong(PLAINTEXT_START).array());
        decryptedHeaderOutputStream.write(ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putLong(PLAINTEXT_END).array());
        decryptedHeaderOutputStream.write(ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putLong(ciphertextStart).array());
        decryptedHeaderOutputStream.write(ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putLong(CTR_OFFSET).array());
        decryptedHeaderOutputStream.write(ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(EncryptionAlgorithm.AES_256_CTR.getCode()).array());
        decryptedHeaderOutputStream.write(sessionKey.getEncoded());
        decryptedHeaderOutputStream.write(ivBytes);
        ByteArrayInputStream decryptedHeaderInputStream = new ByteArrayInputStream(decryptedHeaderOutputStream.toByteArray());

        ByteArrayOutputStream encryptedHeaderOutputStream = new ByteArrayOutputStream();
        Encryptor encryptor = new Encryptor(new Key(key));
        encryptor.setSigningAlgorithm(HashingAlgorithm.Unsigned);
        encryptor.encrypt(decryptedHeaderInputStream, encryptedHeaderOutputStream);
        encryptedHeaderOutputStream.close();
        byte[] encryptedHeader = encryptedHeaderOutputStream.toByteArray();

        out.write(ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).put(PROTOCOL_NAME.getBytes()).array());
        out.write(ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(VERSION).array());
        out.write(ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(HeaderFactory.UNENCRYPTED_HEADER_LENGTH + encryptedHeader.length).array());
        out.write(encryptedHeader);
        if (digest != null) {
            out.write(digest);
        }

        this.out = new CryptoOutputStream(alias, new Properties(), out, sessionKey, new IvParameterSpec(ivBytes));
    }

}
