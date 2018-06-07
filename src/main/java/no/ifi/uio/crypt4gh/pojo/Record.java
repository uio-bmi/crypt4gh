package no.ifi.uio.crypt4gh.pojo;

import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.ToString;

import java.util.Arrays;

@ToString
@EqualsAndHashCode(callSuper = false)
@Data
public class Record extends HeaderEntry {

    private long plaintextStart;
    private long plaintextEnd;
    private long ciphertextStart;
    private long ciphertextEnd;
    private EncryptionAlgorithm algorithm;
    private byte[] key;
    private byte[] iv;

    public Record(byte[] recordBytes) {
        plaintextStart = getLong(Arrays.copyOfRange(recordBytes, 0, 8));
        plaintextEnd = getLong(Arrays.copyOfRange(recordBytes, 8, 16));
        ciphertextStart = getLong(Arrays.copyOfRange(recordBytes, 16, 24));
        ciphertextEnd = getLong(Arrays.copyOfRange(recordBytes, 24, 32));
        int method = getInt(Arrays.copyOfRange(recordBytes, 32, 36));
        algorithm = EncryptionAlgorithm.valueOf(method);
        key = Arrays.copyOfRange(recordBytes, 36, 68);
        iv = Arrays.copyOfRange(recordBytes, 68, 84);
    }

}
