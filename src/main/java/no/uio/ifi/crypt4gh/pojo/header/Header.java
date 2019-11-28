package no.uio.ifi.crypt4gh.pojo.header;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.ToString;
import no.uio.ifi.crypt4gh.pojo.Crypt4GHEntity;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.util.*;

/**
 * Crypt4GH header containing both unencrypted and encrypted payloads.
 */
@ToString
@AllArgsConstructor
public class Header implements Crypt4GHEntity {

    public static final int UNENCRYPTED_HEADER_LENGTH = 8 + 4 + 4;
    public static final String MAGIC_WORD = "crypt4gh";
    public static final int VERSION = 1;

    @Getter
    private final List<HeaderPacket> headerPackets;

    public Header(InputStream inputStream, PrivateKey readerPrivateKey) throws IOException, GeneralSecurityException {
        byte[] unencryptedHeaderBytes = inputStream.readNBytes(UNENCRYPTED_HEADER_LENGTH);
        String magicWord = new String(Arrays.copyOfRange(unencryptedHeaderBytes, 0, 8));
        if (!MAGIC_WORD.equals(magicWord)) {
            throw new GeneralSecurityException("Not a Crypt4GH stream");
        }
        int version = Crypt4GHEntity.getInt(Arrays.copyOfRange(unencryptedHeaderBytes, 8, 12));
        if (VERSION != version) {
            throw new GeneralSecurityException("Unsupported Crypt4GH version: " + version);
        }
        int headerPacketCount = Crypt4GHEntity.getInt(Arrays.copyOfRange(unencryptedHeaderBytes, 12, 16));
        this.headerPackets = new ArrayList<>();
        for (int i = 0; i < headerPacketCount; i++) {
            Optional<HeaderPacket> headerPacketOptional = HeaderPacket.create(inputStream, readerPrivateKey);
            headerPacketOptional.ifPresent(headerPackets::add);
        }
    }

    public Collection<DataEncryptionParameters> getDataEncryptionParametersList() throws GeneralSecurityException {
        Collection<DataEncryptionParameters> result = new ArrayList<>();
        for (HeaderPacket headerPacket : headerPackets) {
            EncryptableHeaderPacket encryptablePayload = headerPacket.getEncryptablePayload();
            HeaderPacketType packetType = encryptablePayload.getPacketType();
            if (packetType == HeaderPacketType.DATA_ENCRYPTION_PARAMETERS) {
                result.add((DataEncryptionParameters) encryptablePayload);
            }
        }
        if (result.isEmpty()) {
            throw new GeneralSecurityException("Data Encryption Parameters not found in the Header");
        }
        return result;
    }

    public void removeDataEditList() {
        Iterator<HeaderPacket> iterator = headerPackets.iterator();
        while (iterator.hasNext()) {
            HeaderPacket headerPacket = iterator.next();
            EncryptableHeaderPacket encryptablePayload = headerPacket.getEncryptablePayload();
            HeaderPacketType packetType = encryptablePayload.getPacketType();
            if (packetType == HeaderPacketType.DATA_EDIT_LIST) {
                iterator.remove();
            }
        }
    }

    public Optional<DataEditList> getDataEditList() {
        for (HeaderPacket headerPacket : headerPackets) {
            EncryptableHeaderPacket encryptablePayload = headerPacket.getEncryptablePayload();
            HeaderPacketType packetType = encryptablePayload.getPacketType();
            if (packetType == HeaderPacketType.DATA_EDIT_LIST) {
                return Optional.of((DataEditList) encryptablePayload);
            }
        }
        return Optional.empty();
    }

    @Override
    public byte[] serialize() throws IOException, GeneralSecurityException {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        byteArrayOutputStream.write(ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).put(MAGIC_WORD.getBytes()).array());
        byteArrayOutputStream.write(ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(VERSION).array());
        byteArrayOutputStream.write(ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(headerPackets.size()).array());
        for (HeaderPacket headerPacket : headerPackets) {
            byteArrayOutputStream.write(headerPacket.serialize());
        }
        return byteArrayOutputStream.toByteArray();
    }

}
