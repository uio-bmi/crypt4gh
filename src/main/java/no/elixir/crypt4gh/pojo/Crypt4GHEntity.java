package no.elixir.crypt4gh.pojo;

import java.io.IOException;
import java.io.Serializable;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.GeneralSecurityException;

/**
 * Crypt4GH entity, mostly to extend Serializable interface, but also to provide LittleEndian conversion methods.
 */
public interface Crypt4GHEntity extends Serializable {

    /**
     * Serializes the entity to a byte array.
     *
     * @return Serialized entity.
     * @throws IOException              In case the serialization fails.
     * @throws GeneralSecurityException In case the encryption fails.
     */
    byte[] serialize() throws IOException, GeneralSecurityException;

    /**
     * Utility method to get little endian integer from byte array.
     *
     * @param bytes Byte array.
     * @return Integer.
     */
    static int getInt(byte[] bytes) {
        return ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN).getInt();
    }

    /**
     * Utility method to get little endian long from byte array.
     *
     * @param bytes Byte array.
     * @return Long.
     */
    static long getLong(byte[] bytes) {
        return ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN).getLong();
    }

}
