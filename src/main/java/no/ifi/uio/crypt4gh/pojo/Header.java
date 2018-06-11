package no.ifi.uio.crypt4gh.pojo;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.ToString;

@ToString
@AllArgsConstructor
@Data
public class Header {

    private final UnencryptedHeader unencryptedHeader;
    private final EncryptedHeader encryptedHeader;

    public long getDataStart() {
        Record record = encryptedHeader.getRecords().iterator().next();
        return unencryptedHeader.getFullHeaderLength() + record.getCiphertextStart();
    }

}
