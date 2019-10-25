package no.uio.ifi.crypt4gh.pojo.header;

import lombok.AllArgsConstructor;

import java.util.Arrays;

/**
 * Header packet types, for now only two available: Data Encryption Parameters and Data Edit List.
 */
@AllArgsConstructor
public enum HeaderPacketType {

    DATA_ENCRYPTION_PARAMETERS(0), DATA_EDIT_LIST(1);

    private int code;

    public int getCode() {
        return code;
    }

    public static HeaderPacketType getByCode(int code) {
        return Arrays.stream(HeaderPacketType.values()).filter(i -> i.code == code).findAny().orElseThrow(RuntimeException::new);
    }

}
