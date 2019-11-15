package no.uio.ifi.crypt4gh.util;

import com.rfksystems.blake2b.Blake2b;
import com.rfksystems.blake2b.security.Blake2bProvider;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.ArrayUtils;

import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.security.*;
import java.security.interfaces.XECPrivateKey;
import java.security.interfaces.XECPublicKey;
import java.security.spec.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;

/**
 * A bunch of methods for generating/constructing/reading/writing/deriving keys.
 */
public class KeyUtils {

    public static final String CHA_CHA_20 = "ChaCha20";
    public static final String X25519 = "X25519";

    public static final String BEGIN_PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----";
    public static final String BEGIN_PRIVATE_KEY = "-----BEGIN PRIVATE KEY-----";
    public static final String END_PUBLIC_KEY = "-----END PUBLIC KEY-----";
    public static final String END_PRIVATE_KEY = "-----END PRIVATE KEY-----";

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
        if (u.length != 32) { // handle the case when U array starts with zero-byte (it gets "eaten" by BigInteger)
            u = ArrayUtils.addAll(new byte[32 - u.length], u);
        }
        ArrayUtils.reverse(u);
        return u;
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
        ArrayUtils.reverse(u);
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
     * Reads PEM file (either public key or private key). Can be both: OpenSSL format or just the bytes representation.
     *
     * @param keyFile Input file to read.
     * @param keyType Type of the key: either PublicKey.class or PrivateKey.class
     * @param <T>     PublicKey or PrivateKey, depending on the second parameter.
     * @return Public or Private key correspondingly.
     * @throws IOException              If the file can't be read.
     * @throws GeneralSecurityException If the key can't be constructed from the given file.
     */
    public <T> T readPEMFile(File keyFile, Class<T> keyType) throws IOException, GeneralSecurityException {
        String keyLines = FileUtils.readFileToString(keyFile, Charset.defaultCharset());
        return readKey(keyLines, keyType);
    }

    /**
     * Reads key from string (either public key or private key). Can be both: OpenSSL format or just the bytes representation.
     *
     * @param keyMaterial Key contents.
     * @param keyType     Type of the key: either PublicKey.class or PrivateKey.class
     * @param <T>         PublicKey or PrivateKey, depending on the second parameter.
     * @return Public or Private key correspondingly.
     * @throws GeneralSecurityException If the key can't be constructed from the given file.
     */
    @SuppressWarnings("unchecked")
    public <T> T readKey(String keyMaterial, Class<T> keyType) throws GeneralSecurityException {
        KeyFactory keyFactory = KeyFactory.getInstance(X25519);
        if (keyType.isAssignableFrom(PublicKey.class)) {
            String keyLine = keyMaterial
                    .replace(BEGIN_PUBLIC_KEY, "")
                    .replace(END_PUBLIC_KEY, "")
                    .replace(System.lineSeparator(), "")
                    .replace(" ", "")
                    .trim();
            byte[] decodedKey = Base64.getDecoder().decode(keyLine);
            try {
                return (T) keyFactory.generatePublic(new X509EncodedKeySpec(decodedKey));
            } catch (InvalidKeySpecException e) { // not an OpenSSL format
                return (T) constructPublicKey(decodedKey);
            }
        }
        if (keyType.isAssignableFrom(PrivateKey.class)) {
            String keyLine = keyMaterial
                    .replace(BEGIN_PRIVATE_KEY, "")
                    .replace(END_PRIVATE_KEY, "")
                    .replace(System.lineSeparator(), "")
                    .replace(" ", "")
                    .trim();
            byte[] decodedKey = Base64.getDecoder().decode(keyLine);
            try {
                return (T) keyFactory.generatePrivate(new PKCS8EncodedKeySpec(decodedKey));
            } catch (InvalidKeySpecException e) { // not an OpenSSL format
                return (T) constructPrivateKey(decodedKey);
            }
        }
        throw new RuntimeException("keyType must be either PublicKey or PrivateKey");
    }

    /**
     * Writes the key to a file.
     *
     * @param keyFile Key file to create.
     * @param key     Key to write.
     * @throws IOException If the file can't be written.
     */
    public void writePEMFile(File keyFile, Key key) throws IOException {
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
