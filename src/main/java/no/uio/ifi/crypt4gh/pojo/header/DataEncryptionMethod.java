package no.uio.ifi.crypt4gh.pojo.header;

import lombok.AllArgsConstructor;
import no.uio.ifi.crypt4gh.pojo.body.ChaCha20IETFPoly1305Segment;
import no.uio.ifi.crypt4gh.pojo.body.Segment;

import java.util.Arrays;

/**
 * Data encryption methods. For now, only ChaCha20-IETF-Poly1305 is supported.
 */
@AllArgsConstructor
public enum DataEncryptionMethod {

    CHACHA20_IETF_POLY1305(0, ChaCha20IETFPoly1305Segment.NONCE_SIZE + Segment.UNENCRYPTED_DATA_SEGMENT_SIZE + ChaCha20IETFPoly1305Segment.MAC_SIZE);

    private int code;
    private int encryptedSegmentSize;

    public int getCode() {
        return code;
    }

    public int getEncryptedSegmentSize() {
        return encryptedSegmentSize;
    }

    public static DataEncryptionMethod getByCode(int code) {
        return Arrays.stream(DataEncryptionMethod.values()).filter(i -> i.code == code).findAny().orElseThrow(RuntimeException::new);
    }

}
