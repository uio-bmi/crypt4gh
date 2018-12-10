package no.uio.ifi.crypt4gh.pojo;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.ToString;

/**
 * Combined (full) Crypt4GH header POJO.
 */
@ToString
@AllArgsConstructor
@Data
public class Header {

    private final UnencryptedHeader unencryptedHeader;
    private final EncryptedHeader encryptedHeader;

}
