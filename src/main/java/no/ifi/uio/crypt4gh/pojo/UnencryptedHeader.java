package no.ifi.uio.crypt4gh.pojo;

import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.ToString;

import java.util.Arrays;

@ToString
@EqualsAndHashCode(callSuper = false)
@Data
public class UnencryptedHeader extends HeaderEntry {

    private String protocolName;
    int version;
    int fullHeaderLength;

    public UnencryptedHeader(byte[] unencryptedHeaderBytes) {
        protocolName = new String(Arrays.copyOfRange(unencryptedHeaderBytes, 0, 8));
        version = getInt(Arrays.copyOfRange(unencryptedHeaderBytes, 8, 12));
        fullHeaderLength = getInt(Arrays.copyOfRange(unencryptedHeaderBytes, 12, 16));
    }


}
