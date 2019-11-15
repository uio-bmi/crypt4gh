package no.uio.ifi.crypt4gh.pojo.body;

import lombok.Data;
import lombok.ToString;
import no.uio.ifi.crypt4gh.pojo.Crypt4GHEntity;
import no.uio.ifi.crypt4gh.pojo.header.ChaCha20IETFPoly1305EncryptionParameters;
import no.uio.ifi.crypt4gh.pojo.header.DataEncryptionMethod;
import no.uio.ifi.crypt4gh.pojo.header.DataEncryptionParameters;

import java.security.GeneralSecurityException;
import java.util.Collection;
import java.util.Optional;

/**
 * Data segment: 65536 bytes long unencrypted and 65564 bytes long encrypted (according to the current spec).
 */
@ToString
@Data
public abstract class Segment implements Crypt4GHEntity {

    public static final int UNENCRYPTED_DATA_SEGMENT_SIZE = 65536;

    protected byte[] unencryptedData;

    public static Segment create(byte[] unencryptedData, DataEncryptionParameters dataEncryptionParameters) throws GeneralSecurityException {
        DataEncryptionMethod dataEncryptionMethod = dataEncryptionParameters.getDataEncryptionMethod();
        switch (dataEncryptionMethod) {
            case CHACHA20_IETF_POLY1305:
                return new ChaCha20IETFPoly1305Segment(unencryptedData, (ChaCha20IETFPoly1305EncryptionParameters) dataEncryptionParameters, true);
            default:
                throw new GeneralSecurityException("Data Encryption Method not found for code: " + dataEncryptionMethod.getCode());
        }
    }

    public static Segment create(byte[] encryptedData, Collection<DataEncryptionParameters> dataEncryptionParametersList) throws GeneralSecurityException {
        for (DataEncryptionParameters dataEncryptionParameters : dataEncryptionParametersList) {
            Optional<Segment> segmentOptional = tryCreate(encryptedData, dataEncryptionParameters);
            if (segmentOptional.isPresent()) {
                return segmentOptional.get();
            }
        }
        throw new GeneralSecurityException("Data Segment can't be decrypted with any of Header keys");
    }

    private static Optional<Segment> tryCreate(byte[] encryptedData, DataEncryptionParameters dataEncryptionParameters) throws GeneralSecurityException {
        DataEncryptionMethod dataEncryptionMethod = dataEncryptionParameters.getDataEncryptionMethod();
        switch (dataEncryptionMethod) {
            case CHACHA20_IETF_POLY1305:
                try {
                    return Optional.of(new ChaCha20IETFPoly1305Segment(encryptedData, (ChaCha20IETFPoly1305EncryptionParameters) dataEncryptionParameters, false));
                } catch (GeneralSecurityException e) {
                    return Optional.empty();
                }
            default:
                throw new GeneralSecurityException("Data Encryption Method not found for code: " + dataEncryptionMethod.getCode());
        }
    }

}
