package no.ifi.uio.crypt4gh.pojo;

import java.util.Arrays;

/**
 * Enum to list supported encryption algorithms.
 */
public enum EncryptionAlgorithm {

    AES_256_CTR(0, "AES/CTR/NoPadding");

    private final int code;
    private final String alias;

    EncryptionAlgorithm(int code, String alias) {
        this.code = code;
        this.alias = alias;
    }

    public int getCode() {
        return code;
    }

    public String getAlias() {
        return alias;
    }

    public static EncryptionAlgorithm valueOf(int code) {
        return Arrays.stream(EncryptionAlgorithm.values()).filter(a -> a.code == code).findAny().orElseThrow(() -> new IllegalArgumentException(String.format("EncryptionAlgorithm with code %s is not supported by the library.", code)));
    }

}
