package no.uio.ifi.crypt4gh.pojo.header;

import lombok.Data;
import lombok.ToString;
import no.uio.ifi.crypt4gh.pojo.Crypt4GHEntity;

import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;

/**
 * Header packet, bearing its length encryption type and encrypted payload.
 */
@ToString
@Data
public abstract class HeaderPacket implements Crypt4GHEntity {

    protected int packetLength;
    protected HeaderEncryptionMethod packetEncryption;
    protected EncryptableHeaderPacket encryptablePayload;

    static HeaderPacket create(InputStream inputStream, PrivateKey readerPrivateKey) throws IOException, GeneralSecurityException {
        int packetLength = Crypt4GHEntity.getInt(inputStream.readNBytes(4));
        int packetEncryptionCode = Crypt4GHEntity.getInt(inputStream.readNBytes(4));
        HeaderEncryptionMethod packetEncryption = HeaderEncryptionMethod.getByCode(packetEncryptionCode);
        byte[] encryptedPayload = inputStream.readNBytes(packetLength - 4 - 4);
        switch (packetEncryption) {
            case X25519_CHACHA20_IETF_POLY1305:
                try {
                    return new X25519ChaCha20IETFPoly1305HeaderPacket(packetLength, encryptedPayload, readerPrivateKey);
                } catch (GeneralSecurityException e) {
                    return null;
                }
            default:
                throw new GeneralSecurityException("Header Encryption Method not found for code: " + packetEncryptionCode);
        }
    }

}
