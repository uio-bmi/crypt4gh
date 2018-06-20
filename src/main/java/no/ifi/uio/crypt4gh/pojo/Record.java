package no.ifi.uio.crypt4gh.pojo;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.ToString;

/**
 * Record aka Encryption Parameters POJO.
 */
@ToString
@AllArgsConstructor
@Data
public class Record {

    private final long plaintextStart;
    private final long plaintextEnd;
    private final long ciphertextStart;
    private final long ctrOffset;
    private final EncryptionAlgorithm algorithm;
    private final byte[] key;
    private final byte[] iv;

}
