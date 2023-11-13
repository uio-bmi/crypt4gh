package no.elixir.crypt4gh.pojo.header;

import lombok.AllArgsConstructor;

import java.util.Arrays;

/**
 * Header encryption methods. For now, only X25519 ChaCha20-IETF-Poly1305 is supported.
 */
@AllArgsConstructor
public enum HeaderEncryptionMethod {

    X25519_CHACHA20_IETF_POLY1305(0);

    private int code;

    public int getCode() {
        return code;
    }

    public static HeaderEncryptionMethod getByCode(int code) {
        return Arrays.stream(HeaderEncryptionMethod.values()).filter(i -> i.code == code).findAny().orElseThrow(RuntimeException::new);
    }

}
