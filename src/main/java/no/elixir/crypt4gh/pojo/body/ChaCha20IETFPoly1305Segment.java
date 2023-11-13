package no.elixir.crypt4gh.pojo.body;

import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.ToString;
import no.elixir.crypt4gh.pojo.EncryptableEntity;
import no.elixir.crypt4gh.pojo.header.ChaCha20IETFPoly1305EncryptionParameters;
import org.apache.commons.lang3.ArrayUtils;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;

import static no.elixir.crypt4gh.pojo.header.X25519ChaCha20IETFPoly1305HeaderPacket.CHA_CHA_20_POLY_1305;

/**
 * Data segment, ChaCha20 encrypted, 65564 bytes long (according to the current spec).
 */
@EqualsAndHashCode(callSuper = true)
@ToString
@Data
public class ChaCha20IETFPoly1305Segment extends Segment implements EncryptableEntity {

    public static final int NONCE_SIZE = 12;
    public static final int MAC_SIZE = 16;

    private byte[] nonce = new byte[NONCE_SIZE];
    private byte[] encryptedData;
    private byte[] mac = new byte[MAC_SIZE];

    ChaCha20IETFPoly1305Segment(byte[] data, ChaCha20IETFPoly1305EncryptionParameters dataEncryptionParameters, boolean encrypt) throws GeneralSecurityException {
        if (encrypt) {
            this.unencryptedData = data;
            encrypt(data, dataEncryptionParameters.getDataKey());
        } else {
            this.nonce = Arrays.copyOfRange(data, 0, NONCE_SIZE);
            this.encryptedData = Arrays.copyOfRange(data, NONCE_SIZE, data.length - MAC_SIZE);
            this.mac = Arrays.copyOfRange(data, data.length - MAC_SIZE, data.length);
            this.unencryptedData = decrypt(dataEncryptionParameters.getDataKey());
        }
    }

    @Override
    public byte[] serialize() throws IOException {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        byteArrayOutputStream.write(ByteBuffer.allocate(NONCE_SIZE).order(ByteOrder.LITTLE_ENDIAN).put(nonce).array());
        byteArrayOutputStream.write(ByteBuffer.allocate(encryptedData.length).order(ByteOrder.LITTLE_ENDIAN).put(encryptedData).array());
        byteArrayOutputStream.write(ByteBuffer.allocate(MAC_SIZE).order(ByteOrder.LITTLE_ENDIAN).put(mac).array());
        return byteArrayOutputStream.toByteArray();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void encrypt(byte[] unencryptedData, SecretKey sharedKey) throws GeneralSecurityException {
        SecureRandom.getInstanceStrong().nextBytes(nonce);
        Cipher cipher = Cipher.getInstance(CHA_CHA_20_POLY_1305);
        cipher.init(Cipher.ENCRYPT_MODE, sharedKey, new IvParameterSpec(nonce));
        byte[] encryptedPayloadWithMAC = cipher.doFinal(unencryptedData);
        encryptedData = Arrays.copyOfRange(encryptedPayloadWithMAC, 0, encryptedPayloadWithMAC.length - MAC_SIZE);
        mac = Arrays.copyOfRange(encryptedPayloadWithMAC, encryptedPayloadWithMAC.length - MAC_SIZE, encryptedPayloadWithMAC.length);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public byte[] decrypt(SecretKey sharedKey) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(CHA_CHA_20_POLY_1305);
        cipher.init(Cipher.DECRYPT_MODE, sharedKey, new IvParameterSpec(nonce));
        return cipher.doFinal(ArrayUtils.addAll(encryptedData, mac));
    }

}

