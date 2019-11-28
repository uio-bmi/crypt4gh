package no.uio.ifi.crypt4gh.util;

import com.rfksystems.blake2b.Blake2b;
import com.rfksystems.blake2b.security.Blake2bProvider;
import no.uio.ifi.crypt4gh.pojo.key.Cipher;
import no.uio.ifi.crypt4gh.pojo.key.KDF;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.ArrayUtils;

import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.Charset;
import java.security.*;
import java.security.interfaces.XECPrivateKey;
import java.security.interfaces.XECPublicKey;
import java.security.spec.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;

import static at.favre.lib.crypto.bcrypt.BCrypt.SALT_LENGTH;
import static no.uio.ifi.crypt4gh.pojo.header.X25519ChaCha20IETFPoly1305HeaderPacket.CHA_CHA_20_POLY_1305;
import static no.uio.ifi.crypt4gh.pojo.header.X25519ChaCha20IETFPoly1305HeaderPacket.NONCE_SIZE;

/**
 * A bunch of methods for generating/constructing/reading/writing/deriving keys.
 */
public class KeyUtils {

    public static final String CHA_CHA_20 = "ChaCha20";
    public static final String X25519 = "X25519";

    public static final String BEGIN_PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----";
    public static final String END_PUBLIC_KEY = "-----END PUBLIC KEY-----";
    public static final String BEGIN_PRIVATE_KEY = "-----BEGIN PRIVATE KEY-----";
    public static final String END_PRIVATE_KEY = "-----END PRIVATE KEY-----";
    public static final String BEGIN_CRYPT4GH_PUBLIC_KEY = "-----BEGIN CRYPT4GH PUBLIC KEY-----";
    public static final String END_CRYPT4GH_PUBLIC_KEY = "-----END CRYPT4GH PUBLIC KEY-----";
    public static final String BEGIN_CRYPT4GH_ENCRYPTED_PRIVATE_KEY = "-----BEGIN CRYPT4GH ENCRYPTED PRIVATE KEY-----";
    public static final String END_CRYPT4GH_ENCRYPTED_PRIVATE_KEY = "-----END CRYPT4GH ENCRYPTED PRIVATE KEY-----";

    public static final String CRYPT4GH_AUTH_MAGIC = "c4gh-v1";

    private static KeyUtils ourInstance = new KeyUtils();

    public static KeyUtils getInstance() {
        return ourInstance;
    }

    private KeyUtils() {
        Security.addProvider(new Blake2bProvider());
    }

    /**
     * Generates X25519 key pair.
     *
     * @return X25519 key pair
     * @throws NoSuchAlgorithmException If the X25519 algorithm is not found.
     */
    public KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(X25519);
        return keyPairGenerator.generateKeyPair();
    }

    /**
     * Extracts either scalar from the X25519 private key, or U from the X25519 public key.
     *
     * @param key Key to extract data from.
     * @return Scalar or U.
     * @throws GeneralSecurityException If the key was not XECPublicKey or XECPrivateKey.
     */
    public byte[] encodeKey(Key key) throws GeneralSecurityException {
        if (key instanceof XECPublicKey) {
            return getU((PublicKey) key);
        }
        if (key instanceof XECPrivateKey) {
            return getScalar((PrivateKey) key);
        }
        throw new GeneralSecurityException("Expected either XECPublicKey or XECPrivateKey, but got: " + key.getClass());
    }

    /**
     * Extracts U from the X25519 public key as a byte array.
     *
     * @param publicKey X25519 public key to extract U from.
     * @return U as byte array.
     * @throws GeneralSecurityException In case U can't be extracted.
     */
    public byte[] getU(PublicKey publicKey) throws GeneralSecurityException {
        KeyFactory keyFactory = KeyFactory.getInstance(X25519);
        XECPublicKeySpec publicKeySpec = keyFactory.getKeySpec(publicKey, XECPublicKeySpec.class);
        byte[] u = publicKeySpec.getU().toByteArray();
        ArrayUtils.reverse(u); // conversion from BigInteger to byte[] reverses array, thus reversing it back
        return Arrays.copyOf(u, 32); // if array ends with zeroes, they will be omitted during conversion, thus appending them back
    }

    /**
     * Extracts scalar from the X25519 private key as a byte array.
     *
     * @param privateKey X25519 private key to extract scalar from.
     * @return Scalar as a byte array.
     * @throws GeneralSecurityException In case scalar can't be extracted.
     */
    public byte[] getScalar(PrivateKey privateKey) throws GeneralSecurityException {
        KeyFactory keyFactory = KeyFactory.getInstance(X25519);
        XECPrivateKeySpec publicKeySpec = keyFactory.getKeySpec(privateKey, XECPrivateKeySpec.class);
        return publicKeySpec.getScalar();
    }

    /**
     * Generates X25519 private key.
     *
     * @return X25519 private key.
     * @throws GeneralSecurityException In case key can't be generated.
     */
    public PrivateKey generatePrivateKey() throws GeneralSecurityException {
        byte[] scalar = new byte[32];
        SecureRandom.getInstanceStrong().nextBytes(scalar);
        return constructPrivateKey(scalar);
    }

    /**
     * Constructs X25519 private key from scalar.
     *
     * @param scalar Scalar to build X25519 private key upon.
     * @return X25519 private key.
     * @throws GeneralSecurityException In case the X25519 private key can't be constructed from the given scalar.
     */
    public PrivateKey constructPrivateKey(byte[] scalar) throws GeneralSecurityException {
        KeyFactory keyFactory = KeyFactory.getInstance(X25519);
        return keyFactory.generatePrivate(new XECPrivateKeySpec(new NamedParameterSpec(X25519), scalar));
    }

    /**
     * Constructs X25519 PUBLIC key from U.
     *
     * @param u U to build X25519 public key upon.
     * @return X25519 public key.
     * @throws GeneralSecurityException In case the X25519 public key can't be constructed from the given U.
     */
    public PublicKey constructPublicKey(byte[] u) throws GeneralSecurityException {
        KeyFactory keyFactory = KeyFactory.getInstance(X25519);
        u = u.clone();
        ArrayUtils.reverse(u); // conversion from byte[] to BigInteger will reverse array, thus reversing it here in the first place
        return keyFactory.generatePublic(new XECPublicKeySpec(new NamedParameterSpec(X25519), new BigInteger(u)));
    }

    /**
     * Derives X25519 public key from the given X25519 private key.
     *
     * @param privateKey X25519 private key to derive public key from.
     * @return Derived X25519 public key.
     * @throws GeneralSecurityException In case X25519 public key can't be derived.
     */
    public PublicKey derivePublicKey(PrivateKey privateKey) throws GeneralSecurityException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(X25519);
        keyPairGenerator.initialize(new NamedParameterSpec(X25519), new StaticSecureRandom(getScalar(privateKey)));
        return keyPairGenerator.generateKeyPair().getPublic();
    }

    /**
     * Generates Diffie Hellman shared key from sender's X25519 private and recipient's X25519 public keys.
     *
     * @param privateKey Sender's X25519 private key.
     * @param publicKey  Recipient's X25519 public key.
     * @return Diffie Hellman shared key.
     * @throws NoSuchAlgorithmException If X25519 algorithm can't be found.
     * @throws InvalidKeyException      If one of the keys is invalid.
     */
    public byte[] generateDiffieHellmanSharedKey(PrivateKey privateKey, PublicKey publicKey) throws NoSuchAlgorithmException, InvalidKeyException {
        KeyAgreement keyAgreement = KeyAgreement.getInstance(X25519);
        keyAgreement.init(privateKey);
        keyAgreement.doPhase(publicKey, true);
        return keyAgreement.generateSecret();
    }

    /**
     * Generates writer's shared key based on sender's X25519 private and recipient's X25519 public keys.
     *
     * @param writerPrivateKey Sender's X25519 private key.
     * @param readerPublicKey  Recipient's X25519 public key.
     * @return Blake2b-based shared key.
     * @throws GeneralSecurityException In case there's a problem in generating keys.
     */
    public SecretKey generateWriterSharedKey(PrivateKey writerPrivateKey, PublicKey readerPublicKey) throws GeneralSecurityException {
        PublicKey writerPublicKey = derivePublicKey(writerPrivateKey);
        byte[] diffieHellmanKey = generateDiffieHellmanSharedKey(writerPrivateKey, readerPublicKey);
        byte[] digest = MessageDigest.getInstance(Blake2b.BLAKE2_B_512).digest(ArrayUtils.addAll(ArrayUtils.addAll(diffieHellmanKey, encodeKey(readerPublicKey)), encodeKey(writerPublicKey)));
        return new SecretKeySpec(Arrays.copyOfRange(digest, 0, 32), CHA_CHA_20);
    }

    /**
     * Generates reader's shared key based on recipient's X25519 private and sender's X25519 public keys.
     *
     * @param readerPrivateKey Recipient's X25519 private key.
     * @param writerPublicKey  Sender's X25519 public key.
     * @return Blake2b-based shared key.
     * @throws GeneralSecurityException In case there's a problem in generating keys.
     */
    public SecretKey generateReaderSharedKey(PrivateKey readerPrivateKey, PublicKey writerPublicKey) throws GeneralSecurityException {
        PublicKey readerPublicKey = derivePublicKey(readerPrivateKey);
        byte[] diffieHellmanKey = generateDiffieHellmanSharedKey(readerPrivateKey, writerPublicKey);
        byte[] digest = MessageDigest.getInstance(Blake2b.BLAKE2_B_512).digest(ArrayUtils.addAll(ArrayUtils.addAll(diffieHellmanKey, encodeKey(readerPublicKey)), encodeKey(writerPublicKey)));
        return new SecretKeySpec(Arrays.copyOfRange(digest, 0, 32), CHA_CHA_20);
    }

    /**
     * Generates ChaCha20 secret key.
     *
     * @return ChaCha20 secret key.
     * @throws NoSuchAlgorithmException If ChaCha20 algorithm can't be found.
     */
    public SecretKey generateSessionKey() throws NoSuchAlgorithmException {
        return KeyGenerator.getInstance(CHA_CHA_20).generateKey();
    }

    /**
     * Reads public key (OpenSSL or Crypt4GH format) file.
     *
     * @param keyFile Public key file.
     * @return Public key.
     * @throws IOException              If the file can't be read.
     * @throws GeneralSecurityException If the key can't be constructed from the given file.
     */
    public PublicKey readPublicKey(File keyFile) throws IOException, GeneralSecurityException {
        String keyLines = FileUtils.readFileToString(keyFile, Charset.defaultCharset());
        return readPublicKey(keyLines);
    }

    /**
     * Reads public key (OpenSSL or Crypt4GH format).
     *
     * @param keyMaterial Content of the key file.
     * @return Public key.
     * @throws GeneralSecurityException If the key can't be constructed from the given content.
     */
    public PublicKey readPublicKey(String keyMaterial) throws GeneralSecurityException {
        KeyFactory keyFactory = KeyFactory.getInstance(X25519);
        byte[] decodedKey = decodeKey(keyMaterial);
        try {
            return keyFactory.generatePublic(new X509EncodedKeySpec(decodedKey));
        } catch (InvalidKeySpecException e) {
            return constructPublicKey(decodedKey);
        }
    }

    /**
     * Reads private key (OpenSSL or Crypt4GH format) file.
     *
     * @param keyFile  Private key file.
     * @param password Optional password (if private key is password-protected). Can be null for unencrypted key.
     * @return Private key.
     * @throws IOException              If the file can't be read.
     * @throws GeneralSecurityException If the key can't be constructed from the given file.
     */
    public PrivateKey readPrivateKey(File keyFile, char[] password) throws IOException, GeneralSecurityException {
        String keyLines = FileUtils.readFileToString(keyFile, Charset.defaultCharset());
        return readPrivateKey(keyLines, password);
    }

    /**
     * Reads private key (OpenSSL or Crypt4GH format) file.
     *
     * @param keyMaterial Content of the key file.
     * @param password    Optional password (if private key is encrypted).
     * @return Private key.
     * @throws GeneralSecurityException If the key can't be constructed from the given content.
     * @throws IllegalArgumentException If the key is password-protected, but the password was <code>null</code>.
     */
    public PrivateKey readPrivateKey(String keyMaterial, char[] password) throws GeneralSecurityException, IllegalArgumentException {
        KeyFactory keyFactory = KeyFactory.getInstance(X25519);
        byte[] decodedKey = decodeKey(keyMaterial);
        try {
            return keyFactory.generatePrivate(new PKCS8EncodedKeySpec(decodedKey));
        } catch (InvalidKeySpecException e) {
            return readCrypt4GHPrivateKey(decodedKey, password);
        }
    }

    /**
     * Reads Crypt4GH private key.
     *
     * @param keyMaterial Decoded key file content.
     * @param password    Optional password (if private key is password-protected). Can be null for unencrypted key.
     * @return Private key.
     * @throws GeneralSecurityException If the key can't be constructed from the given content.
     * @throws IllegalArgumentException If the key is password-protected, but the password was <code>null</code>.
     */
    public PrivateKey readCrypt4GHPrivateKey(byte[] keyMaterial, char[] password) throws GeneralSecurityException, IllegalArgumentException {
        ByteBuffer byteBuffer = ByteBuffer.wrap(keyMaterial).order(ByteOrder.BIG_ENDIAN);
        byteBuffer.get(new byte[CRYPT4GH_AUTH_MAGIC.length()]);
        KDF kdf = KDF.valueOf(decodeString(byteBuffer).toUpperCase());
        int rounds = 0;
        byte[] salt = new byte[0];
        if (kdf != KDF.NONE) {
            if (password == null) {
                throw new IllegalArgumentException("Private key is password-protected, need a password for decryption");
            }
            short roundsAndSaltLength = byteBuffer.getShort();
            int saltLength = roundsAndSaltLength - 4;
            rounds = byteBuffer.getInt();
            salt = decodeArray(byteBuffer, saltLength);
        }
        Cipher cipher = Cipher.valueOf(decodeString(byteBuffer).toUpperCase());
        short keyLength = byteBuffer.getShort();
        byte[] payload = decodeArray(byteBuffer, keyLength);
        if (kdf == KDF.NONE) {
            if (cipher != Cipher.NONE) {
                throw new GeneralSecurityException("Invalid private key: KDF is 'none', but cipher is not 'none");
            }
            return constructPrivateKey(payload);
        }
        SecretKeySpec derivedKey = new SecretKeySpec(kdf.derive(rounds, password, salt), CHA_CHA_20);
        Arrays.fill(password, (char) 0);
        javax.crypto.Cipher decryption = javax.crypto.Cipher.getInstance(CHA_CHA_20_POLY_1305);
        byte[] nonce = Arrays.copyOfRange(payload, 0, NONCE_SIZE);
        byte[] key = Arrays.copyOfRange(payload, NONCE_SIZE, payload.length);
        decryption.init(javax.crypto.Cipher.DECRYPT_MODE, derivedKey, new IvParameterSpec(nonce));
        byte[] decryptedPayload = decryption.doFinal(key);
        return constructPrivateKey(decryptedPayload);
    }

    /**
     * Decodes Base64 key string, surrounded by header and footer.
     *
     * @param keyMaterial Base64 key string, surrounded by header and footer.
     * @return Decoded key as byte array.
     */
    public byte[] decodeKey(String keyMaterial) {
        keyMaterial = keyMaterial.replaceAll("-----(.*)-----", "").replace(System.lineSeparator(), "").replace(" ", "").trim();
        return Base64.getDecoder().decode(keyMaterial);
    }

    /**
     * Writes the key to a file in OpenSSL format.
     *
     * @param keyFile Key file to create.
     * @param key     Key to write.
     * @throws IOException If the file can't be written.
     */
    public void writeOpenSSLKey(File keyFile, Key key) throws IOException {
        Collection<String> keyLines = new ArrayList<>();
        boolean isPublic = key instanceof PublicKey;
        if (isPublic) {
            keyLines.add(BEGIN_PUBLIC_KEY);
        } else {
            keyLines.add(BEGIN_PRIVATE_KEY);
        }
        keyLines.add(Base64.getEncoder().encodeToString(key.getEncoded()));
        if (isPublic) {
            keyLines.add(END_PUBLIC_KEY);
        } else {
            keyLines.add(END_PRIVATE_KEY);
        }
        FileUtils.writeLines(keyFile, keyLines);
    }

    /**
     * Writes the key to a file in Crypt4GH format.
     *
     * @param keyFile  Key file to create.
     * @param key      Key to write.
     * @param password Password to lock private key.
     * @throws IOException If the file can't be written.
     */
    public void writeCrypt4GHKey(File keyFile, Key key, char[] password) throws IOException, GeneralSecurityException {
        Collection<String> keyLines = new ArrayList<>();
        boolean isPublic = key instanceof PublicKey;
        byte[] encodedKey = encodeKey(key);
        if (isPublic) {
            keyLines.add(BEGIN_CRYPT4GH_PUBLIC_KEY);
            keyLines.add(Base64.getEncoder().encodeToString(encodedKey));
            keyLines.add(END_CRYPT4GH_PUBLIC_KEY);
        } else {
            byte[] salt = new byte[SALT_LENGTH];
            SecureRandom.getInstanceStrong().nextBytes(salt);
            SecretKeySpec derivedKey = new SecretKeySpec(KDF.SCRYPT.derive(0, password, salt), CHA_CHA_20);
            Arrays.fill(password, (char) 0);
            byte[] nonce = new byte[NONCE_SIZE];
            SecureRandom.getInstanceStrong().nextBytes(nonce);
            javax.crypto.Cipher encryption = javax.crypto.Cipher.getInstance(CHA_CHA_20_POLY_1305);
            encryption.init(javax.crypto.Cipher.ENCRYPT_MODE, derivedKey, new IvParameterSpec(nonce));
            byte[] encryptedKey = encryption.doFinal(encodedKey);

            keyLines.add(BEGIN_CRYPT4GH_ENCRYPTED_PRIVATE_KEY);
            try (ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream()) {
                byteArrayOutputStream.write(CRYPT4GH_AUTH_MAGIC.getBytes());
                byteArrayOutputStream.write(encodeString(KDF.SCRYPT.name().toLowerCase()));
                byteArrayOutputStream.write(encodeArray(ArrayUtils.addAll(new byte[4], salt)));
                byteArrayOutputStream.write(encodeString(Cipher.CHACHA20_POLY1305.name().toLowerCase()));
                byteArrayOutputStream.write(encodeArray(ArrayUtils.addAll(nonce, encryptedKey)));
                keyLines.add(Base64.getEncoder().encodeToString(byteArrayOutputStream.toByteArray()));
            }
            keyLines.add(END_CRYPT4GH_ENCRYPTED_PRIVATE_KEY);
        }
        FileUtils.writeLines(keyFile, keyLines);
    }

    private String decodeString(ByteBuffer byteBuffer) {
        short length = byteBuffer.getShort();
        return new String(decodeArray(byteBuffer, length));
    }

    private byte[] decodeArray(ByteBuffer byteBuffer, int length) {
        byte[] array = new byte[length];
        byteBuffer.get(array);
        return array;
    }

    private byte[] encodeString(String string) {
        short length = (short) string.length();
        return ByteBuffer.allocate(2 + length).order(ByteOrder.BIG_ENDIAN).putShort(length).put(string.getBytes()).array();
    }

    private byte[] encodeArray(byte[] array) {
        short length = (short) array.length;
        return ByteBuffer.allocate(2 + length).order(ByteOrder.BIG_ENDIAN).putShort(length).put(array).array();
    }

    private static class StaticSecureRandom extends SecureRandom {

        private final byte[] privateKey;

        StaticSecureRandom(byte[] privateKey) {
            this.privateKey = privateKey.clone();
        }

        @Override
        public void nextBytes(byte[] bytes) {
            System.arraycopy(privateKey, 0, bytes, 0, privateKey.length);
        }

    }

}
