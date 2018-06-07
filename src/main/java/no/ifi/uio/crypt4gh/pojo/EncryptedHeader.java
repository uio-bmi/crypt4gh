package no.ifi.uio.crypt4gh.pojo;

import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.ToString;
import org.bouncycastle.openpgp.PGPException;
import org.c02e.jpgpj.Decryptor;
import org.c02e.jpgpj.Key;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@ToString
@EqualsAndHashCode(callSuper = false)
@Data
public class EncryptedHeader extends HeaderEntry {

    private List<Record> records = new ArrayList<>();

    public EncryptedHeader(byte[] encryptedHeaderBytes, String key, String passphrase) throws IOException, PGPException {
        Decryptor decryptor = new Decryptor(new Key(key, passphrase));
        decryptor.setVerificationRequired(false);
        ByteArrayOutputStream decryptedHeaderStream = new ByteArrayOutputStream();
        decryptor.decrypt(new ByteArrayInputStream(encryptedHeaderBytes), decryptedHeaderStream);
        byte[] decryptedHeader = decryptedHeaderStream.toByteArray();
        int numberOfRecords = getInt(Arrays.copyOfRange(decryptedHeader, 0, 4));
        for (int i = 0; i < numberOfRecords; i++) {
            records.add(new Record(Arrays.copyOfRange(decryptedHeader, 4 + 84 * i, 4 + 84 * (i + 1))));
        }
    }


}
