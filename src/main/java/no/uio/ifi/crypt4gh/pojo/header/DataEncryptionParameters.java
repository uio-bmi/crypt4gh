package no.uio.ifi.crypt4gh.pojo.header;

import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.ToString;
import no.uio.ifi.crypt4gh.pojo.Crypt4GHEntity;

import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;

/**
 * Data Encryption Parameters, bears Data Encryption Method.
 */
@EqualsAndHashCode(callSuper = true)
@ToString
@Data
public abstract class DataEncryptionParameters extends EncryptableHeaderPacket {

    protected DataEncryptionMethod dataEncryptionMethod;

    public static DataEncryptionParameters create(InputStream inputStream) throws IOException, GeneralSecurityException {
        int dataEncryptionMethodCode = Crypt4GHEntity.getInt(inputStream.readNBytes(4));
        DataEncryptionMethod dataEncryptionMethod = DataEncryptionMethod.getByCode(dataEncryptionMethodCode);
        switch (dataEncryptionMethod) {
            case CHACHA20_IETF_POLY1305:
                return new ChaCha20IETFPoly1305EncryptionParameters(inputStream);
            default:
                throw new GeneralSecurityException("Data Encryption Method not found for code: " + dataEncryptionMethodCode);
        }
    }

}
