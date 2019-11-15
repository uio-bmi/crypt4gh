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

    public static final String CHA_CHA_20 = "ChaCha20";
    public static final String X25519 = "X25519";

    private static Crypt4GHUtils ourInstance = new Crypt4GHUtils();

    public static Crypt4GHUtils getInstance() {
        return ourInstance;
    }

    private Crypt4GHUtils() {
        Security.addProvider(new Blake2bProvider());
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
            addRecipient(header, privateKeyForDecryption, newRecipientPublicKey);
            return header;
        }
    }

    private void addRecipient(Header header, PrivateKey privateKeyForDecryption, PublicKey newRecipientPublicKey) throws IOException, GeneralSecurityException {
        List<HeaderPacket> headerPackets = new ArrayList<>(header.getHeaderPackets());
        for (HeaderPacket headerPacket : headerPackets) {
            HeaderEncryptionMethod packetEncryption = headerPacket.getPacketEncryption();
            switch (packetEncryption) {
                case X25519_CHACHA20_IETF_POLY1305:
                    HeaderPacket newHeaderPacket = new X25519ChaCha20IETFPoly1305HeaderPacket(headerPacket.getEncryptablePayload(), privateKeyForDecryption, newRecipientPublicKey);
                    header.getHeaderPackets().add(newHeaderPacket);
                    break;
                default:
                    throw new GeneralSecurityException("Header Encryption Method not supported: " + packetEncryption.getCode());
            }
        }
    }

}
