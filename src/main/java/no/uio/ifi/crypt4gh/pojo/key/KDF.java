package no.uio.ifi.crypt4gh.pojo.key;

import at.favre.lib.crypto.bkdf.BKDF;
import com.lambdaworks.crypto.SCrypt;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.spec.KeySpec;
import java.util.Arrays;

/**
 * Key Derivation Function.
 */
public enum KDF {

    SCRYPT, BCRYPT, PBKDF2_HMAC_SHA256, NONE;

    public static final int KEY_LENGTH = 32;
    public static final String PBKDF_2_WITH_HMAC_SHA_256 = "PBKDF2WithHmacSHA256";

    /**
     * Derives key, depending on the KDF.
     *
     * @param rounds   Number of iterations.
     * @param password Password.
     * @param salt     Salt.
     * @return Derived key.
     * @throws GeneralSecurityException If key can't be derived.
     */
    public byte[] derive(int rounds, char[] password, byte[] salt) throws GeneralSecurityException {
        switch (this) {
            case SCRYPT:
                return SCrypt.scrypt(toBytes(password), salt, 1 << 14, 8, 1, KEY_LENGTH);
            case BCRYPT:
                return BKDF.createKdf().derive(salt, password, (int) (Math.log(rounds) / Math.log(2)), null, KEY_LENGTH);
            case PBKDF2_HMAC_SHA256:
                KeySpec spec = new PBEKeySpec(password, salt, rounds, KEY_LENGTH);
                SecretKeyFactory factory = SecretKeyFactory.getInstance(PBKDF_2_WITH_HMAC_SHA_256);
                return factory.generateSecret(spec).getEncoded();
            case NONE:
                throw new GeneralSecurityException("Can't derive key with 'none' KDF");
            default:
                throw new GeneralSecurityException("KDF not found");
        }
    }

    // conversion without String creation for a better security
    private byte[] toBytes(char[] chars) {
        CharBuffer charBuffer = CharBuffer.wrap(chars);
        ByteBuffer byteBuffer = StandardCharsets.UTF_8.encode(charBuffer);
        byte[] bytes = Arrays.copyOfRange(byteBuffer.array(), byteBuffer.position(), byteBuffer.limit());
        Arrays.fill(byteBuffer.array(), (byte) 0);
        return bytes;
    }

}
