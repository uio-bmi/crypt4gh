package no.uio.ifi.crypt4gh.pojo.header;

import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.ToString;
import no.uio.ifi.crypt4gh.pojo.EncryptableEntity;
import no.uio.ifi.crypt4gh.util.KeyUtils;
import org.apache.commons.lang3.ArrayUtils;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * X25519 ChaCha20-IETF-Poly1305 encrypted header packet.
 */
@EqualsAndHashCode(callSuper = true)
@ToString
@Data
public class X25519ChaCha20IETFPoly1305HeaderPacket extends HeaderPacket implements EncryptableEntity {

    public static final String CHA_CHA_20_POLY_1305 = "ChaCha20-Poly1305";
    public static final int NONCE_SIZE = 12;
    public static final int MAC_SIZE = 16;

    private PublicKey writerPublicKey;
    private byte[] nonce = new byte[NONCE_SIZE];
    private byte[] encryptedPayload;
    private byte[] mac = new byte[MAC_SIZE];

    public X25519ChaCha20IETFPoly1305HeaderPacket(EncryptableHeaderPacket encryptablePayload, PrivateKey writerPrivateKey, PublicKey readerPublicKey) throws GeneralSecurityException, IOException {
        this.packetEncryption = HeaderEncryptionMethod.X25519_CHACHA20_IETF_POLY1305;
        this.writerPublicKey = KeyUtils.getInstance().derivePublicKey(writerPrivateKey);
        this.encryptablePayload = encryptablePayload;
        SecretKey sharedKey = KeyUtils.getInstance().generateWriterSharedKey(writerPrivateKey, readerPublicKey);
        encrypt(encryptablePayload.serialize(), sharedKey);
        this.packetLength = 4               // packetLength length itself
                + 4                         // encryption method length
                + 32                        // writer public key length
                + NONCE_SIZE
                + encryptedPayload.length   // encrypted payload length (with nonce and MAC)
                + MAC_SIZE;
    }

    public X25519ChaCha20IETFPoly1305HeaderPacket(int packetLength, byte[] headerPacketBody, PrivateKey readerPrivateKey) throws IOException, GeneralSecurityException {
        this.packetEncryption = HeaderEncryptionMethod.X25519_CHACHA20_IETF_POLY1305;
        this.writerPublicKey = KeyUtils.getInstance().constructPublicKey(Arrays.copyOfRange(headerPacketBody, 0, 32));
        this.nonce = Arrays.copyOfRange(headerPacketBody, 32, 32 + NONCE_SIZE);
        this.encryptedPayload = Arrays.copyOfRange(headerPacketBody, 32 + NONCE_SIZE, headerPacketBody.length - MAC_SIZE);
        this.mac = Arrays.copyOfRange(headerPacketBody, headerPacketBody.length - MAC_SIZE, headerPacketBody.length);
        this.packetLength = packetLength;
        SecretKey sharedKey = KeyUtils.getInstance().generateReaderSharedKey(readerPrivateKey, writerPublicKey);
        byte[] decryptedPayloadBytes = decrypt(sharedKey);
        this.encryptablePayload = EncryptableHeaderPacket.create(new ByteArrayInputStream(decryptedPayloadBytes));
    }

    @Override
    public byte[] serialize() throws IOException, GeneralSecurityException {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        byteArrayOutputStream.write(ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(packetLength).array());
        byteArrayOutputStream.write(ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(packetEncryption.getCode()).array());
        byteArrayOutputStream.write(ByteBuffer.allocate(32).order(ByteOrder.LITTLE_ENDIAN).put(KeyUtils.getInstance().encodeKey(writerPublicKey)).array());
        byteArrayOutputStream.write(ByteBuffer.allocate(NONCE_SIZE).order(ByteOrder.LITTLE_ENDIAN).put(nonce).array());
        byteArrayOutputStream.write(ByteBuffer.allocate(encryptedPayload.length).order(ByteOrder.LITTLE_ENDIAN).put(encryptedPayload).array());
        byteArrayOutputStream.write(ByteBuffer.allocate(MAC_SIZE).order(ByteOrder.LITTLE_ENDIAN).put(mac).array());
        return byteArrayOutputStream.toByteArray();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void encrypt(byte[] unencryptedBytes, SecretKey sharedKey) throws GeneralSecurityException {
        SecureRandom.getInstanceStrong().nextBytes(nonce);
        Cipher cipher = Cipher.getInstance(CHA_CHA_20_POLY_1305);
        cipher.init(Cipher.ENCRYPT_MODE, sharedKey, new IvParameterSpec(nonce));
        byte[] encryptedPayloadWithMAC = cipher.doFinal(unencryptedBytes);
        encryptedPayload = Arrays.copyOfRange(encryptedPayloadWithMAC, 0, encryptedPayloadWithMAC.length - MAC_SIZE);
        mac = Arrays.copyOfRange(encryptedPayloadWithMAC, encryptedPayloadWithMAC.length - MAC_SIZE, encryptedPayloadWithMAC.length);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public byte[] decrypt(SecretKey sharedKey) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(CHA_CHA_20_POLY_1305);
        cipher.init(Cipher.DECRYPT_MODE, sharedKey, new IvParameterSpec(nonce));
        return cipher.doFinal(ArrayUtils.addAll(encryptedPayload, mac));
    }

}
