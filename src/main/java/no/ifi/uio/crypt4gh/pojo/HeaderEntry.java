package no.ifi.uio.crypt4gh.pojo;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public abstract class HeaderEntry {

    protected int getInt(byte[] bytes) {
        return ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN).getInt();
    }

    protected long getLong(byte[] bytes) {
        return ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN).getLong();
    }

}
