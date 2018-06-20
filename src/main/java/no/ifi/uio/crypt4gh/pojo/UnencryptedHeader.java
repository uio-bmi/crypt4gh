package no.ifi.uio.crypt4gh.pojo;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.ToString;

/**
 * Unencrypted Crypt4GH header POJO.
 */
@ToString
@AllArgsConstructor
@Data
public class UnencryptedHeader {

    private final String protocolName;
    private final int version;
    private final int fullHeaderLength;

}
