package no.uio.ifi.crypt4gh.util;

import com.rfksystems.blake2b.security.Blake2bProvider;
import no.uio.ifi.crypt4gh.pojo.header.Header;
import no.uio.ifi.crypt4gh.pojo.header.HeaderEncryptionMethod;
import no.uio.ifi.crypt4gh.pojo.header.HeaderPacket;
import no.uio.ifi.crypt4gh.pojo.header.X25519ChaCha20IETFPoly1305HeaderPacket;
import no.uio.ifi.crypt4gh.stream.Crypt4GHInputStream;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;

/**
 * A bunch of methods mostly for working with Crypt4GH headers.
 */
public class Crypt4GHUtils {

    private static Crypt4GHUtils ourInstance = new Crypt4GHUtils();

    public static Crypt4GHUtils getInstance() {
        return ourInstance;
    }

    private Crypt4GHUtils() {
        Security.addProvider(new Blake2bProvider());
    }

    /**
     * Sets recipient to a header.
     *
     * @param serializedHeader        Serialized header to set recipient to.
     * @param privateKeyForDecryption Private key top decrypt the header.
     * @param newRecipientPublicKey   Public key of a new recipient.
     * @return Header with recipient set.
     * @throws IOException              In case of I/O error.
     * @throws GeneralSecurityException In case of encryption related error.
     */
    public Header setRecipient(byte[] serializedHeader, PrivateKey privateKeyForDecryption, PublicKey newRecipientPublicKey) throws IOException, GeneralSecurityException {
        try (ByteArrayInputStream headerInputStream = new ByteArrayInputStream(serializedHeader);
             Crypt4GHInputStream crypt4GHInputStream = new Crypt4GHInputStream(headerInputStream, privateKeyForDecryption)) {
            Header header = crypt4GHInputStream.getHeader();
            List<HeaderPacket> headerPacketsWithNewRecipient = getHeaderPacketsWithNewRecipient(header, privateKeyForDecryption, newRecipientPublicKey);
            return new Header(headerPacketsWithNewRecipient);
        }
    }

    /**
     * Adds recipient to a header.
     *
     * @param serializedHeader        Serialized header to add recipient to.
     * @param privateKeyForDecryption Private key top decrypt the header.
     * @param newRecipientPublicKey   Public key of a new recipient.
     * @return Header with added recipient.
     * @throws IOException              In case of I/O error.
     * @throws GeneralSecurityException In case of encryption related error.
     */
    public Header addRecipient(byte[] serializedHeader, PrivateKey privateKeyForDecryption, PublicKey newRecipientPublicKey) throws IOException, GeneralSecurityException {
        try (ByteArrayInputStream headerInputStream = new ByteArrayInputStream(serializedHeader);
             Crypt4GHInputStream crypt4GHInputStream = new Crypt4GHInputStream(headerInputStream, privateKeyForDecryption)) {
            Header header = crypt4GHInputStream.getHeader();
            List<HeaderPacket> headerPacketsWithNewRecipient = getHeaderPacketsWithNewRecipient(header, privateKeyForDecryption, newRecipientPublicKey);
            header.getHeaderPackets().addAll(headerPacketsWithNewRecipient);
            return header;
        }
    }

    private List<HeaderPacket> getHeaderPacketsWithNewRecipient(Header header, PrivateKey privateKeyForDecryption, PublicKey newRecipientPublicKey) throws IOException, GeneralSecurityException {
        List<HeaderPacket> result = new ArrayList<>();
        for (HeaderPacket headerPacket : header.getHeaderPackets()) {
            HeaderEncryptionMethod packetEncryption = headerPacket.getPacketEncryption();
            switch (packetEncryption) {
                case X25519_CHACHA20_IETF_POLY1305:
                    HeaderPacket newHeaderPacket = new X25519ChaCha20IETFPoly1305HeaderPacket(headerPacket.getEncryptablePayload(), privateKeyForDecryption, newRecipientPublicKey);
                    result.add(newHeaderPacket);
                    break;
                default:
                    throw new GeneralSecurityException("Header Encryption Method not supported: " + packetEncryption.getCode());
            }
        }
        return result;
    }

}
