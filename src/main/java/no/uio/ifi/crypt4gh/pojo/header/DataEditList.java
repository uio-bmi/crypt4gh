package no.uio.ifi.crypt4gh.pojo.header;

import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.ToString;
import no.uio.ifi.crypt4gh.pojo.Crypt4GHEntity;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * Data Edit List.
 */
@EqualsAndHashCode(callSuper = true)
@ToString
@Data
public class DataEditList extends EncryptableHeaderPacket {

    private int numberLengths;
    private long[] lengths;

    public DataEditList(int numberLengths, long[] lengths) {
        this.packetType = HeaderPacketType.DATA_EDIT_LIST;
        this.numberLengths = numberLengths;
        this.lengths = lengths;
    }

    DataEditList(InputStream inputStream) throws IOException {
        this.packetType = HeaderPacketType.DATA_EDIT_LIST;
        this.numberLengths = Crypt4GHEntity.getInt(inputStream.readNBytes(4));
        this.lengths = new long[numberLengths];
        for (int i = 0; i < numberLengths; i++) {
            lengths[i] = new BigInteger(inputStream.readNBytes(8)).longValue();
        }
    }

    @Override
    public byte[] serialize() throws IOException {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        byteArrayOutputStream.write(ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(packetType.getCode()).array());
        byteArrayOutputStream.write(ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(numberLengths).array());
        for (long length : lengths) {
            byteArrayOutputStream.write(ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putLong(length).array());
        }
        return byteArrayOutputStream.toByteArray();
    }

}
