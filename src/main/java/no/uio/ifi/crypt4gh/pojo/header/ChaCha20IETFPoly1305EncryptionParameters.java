package no.uio.ifi.crypt4gh.pojo.header;

import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.ToString;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * ChaCha20-IETF-Poly1305 Data Encryption Parameters.
 */
@EqualsAndHashCode(callSuper = true)
@ToString
@Data
public class ChaCha20IETFPoly1305EncryptionParameters extends DataEncryptionParameters {

    public static final String CHA_CHA_20 = "ChaCha20";

    private SecretKey dataKey;

    public ChaCha20IETFPoly1305EncryptionParameters(SecretKey dataKey) {
        this.packetType = HeaderPacketType.DATA_ENCRYPTION_PARAMETERS;
        this.dataEncryptionMethod = DataEncryptionMethod.CHACHA20_IETF_POLY1305;
        this.dataKey = dataKey;
    }

    ChaCha20IETFPoly1305EncryptionParameters(InputStream inputStream) throws IOException {
        this.packetType = HeaderPacketType.DATA_ENCRYPTION_PARAMETERS;
        this.dataEncryptionMethod = DataEncryptionMethod.CHACHA20_IETF_POLY1305;
        this.dataKey = new SecretKeySpec(inputStream.readNBytes(32), CHA_CHA_20);
    }

    @Override
    public byte[] serialize() throws IOException {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        byteArrayOutputStream.write(ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(packetType.getCode()).array());
        byteArrayOutputStream.write(ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(dataEncryptionMethod.getCode()).array());
        byteArrayOutputStream.write(ByteBuffer.allocate(32).order(ByteOrder.LITTLE_ENDIAN).put(dataKey.getEncoded()).array());
        return byteArrayOutputStream.toByteArray();
    }

}

