package no.elixir.crypt4gh.pojo;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.security.GeneralSecurityException;

/**
 * Crypt4GH entity that is supposed to be encrypted/decrypted.
 */
public interface EncryptableEntity {

    /**
     * Encrypts the entity.
     *
     * @param unencryptedBytes Raw data bytes.
     * @param sharedKey        Secret key to encrypt with.
     * @throws IOException              In case of in-memory streaming error.
     * @throws GeneralSecurityException In case of encryption error.
     */
    void encrypt(byte[] unencryptedBytes, SecretKey sharedKey) throws IOException, GeneralSecurityException;

    /**
     * Decrypts the entity.
     *
     * @param sharedKey Secret key to use for decryption.
     * @return Raw data bytes.
     * @throws GeneralSecurityException In case of decryption error.
     */
    byte[] decrypt(SecretKey sharedKey) throws GeneralSecurityException;

}
