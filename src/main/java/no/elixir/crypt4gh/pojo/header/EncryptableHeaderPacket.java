package no.elixir.crypt4gh.pojo.header;

import lombok.Data;
import lombok.ToString;
import no.elixir.crypt4gh.pojo.Crypt4GHEntity;

import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;

/**
 * Header packet that can be encrypted, bears packet type.
 */
@ToString
@Data
public abstract class EncryptableHeaderPacket implements Crypt4GHEntity {

    protected HeaderPacketType packetType;

    static EncryptableHeaderPacket create(InputStream inputStream) throws IOException, GeneralSecurityException {
        int headerPacketTypeCode = Crypt4GHEntity.getInt(inputStream.readNBytes(4));
        HeaderPacketType headerPacketType = HeaderPacketType.getByCode(headerPacketTypeCode);
        switch (headerPacketType) {
            case DATA_ENCRYPTION_PARAMETERS:
                return DataEncryptionParameters.create(inputStream);
            case DATA_EDIT_LIST:
                return new DataEditList(inputStream);
            default:
                throw new GeneralSecurityException("Header Packet Type not found for code: " + headerPacketTypeCode);
        }
    }

}
