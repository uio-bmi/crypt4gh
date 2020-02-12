package no.uio.ifi.crypt4gh.stream;

import no.uio.ifi.crypt4gh.pojo.body.Segment;
import no.uio.ifi.crypt4gh.pojo.header.*;
import no.uio.ifi.crypt4gh.util.KeyUtils;

import javax.crypto.SecretKey;
import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static no.uio.ifi.crypt4gh.pojo.body.Segment.UNENCRYPTED_DATA_SEGMENT_SIZE;

/**
 * Crypt4GHOutputStream that wraps existing OutputStream.
 */
public class Crypt4GHOutputStream extends FilterOutputStream {

    private Header header;
    private byte[] buffer = new byte[UNENCRYPTED_DATA_SEGMENT_SIZE];
    private int bytesCached;
    private DataEncryptionParameters dataEncryptionParameters;

    /**
     * Constructs the Crypt4GHOutputStream by wrapping existing OutputStream.
     *
     * @param out              Existing OutputStream.
     * @param writerPrivateKey Sender's private key.
     * @param readerPublicKey  Recipient's public key.
     * @throws IOException              In case the Crypt4GH header can't be read from the underlying OutputStream.
     * @throws GeneralSecurityException In case the Crypt4GH header is malformed.
     */
    public Crypt4GHOutputStream(OutputStream out, PrivateKey writerPrivateKey, PublicKey readerPublicKey) throws IOException, GeneralSecurityException {
        super(out);
        KeyUtils keyUtils = KeyUtils.getInstance();
        SecretKey dataKey = keyUtils.generateSessionKey();
        this.dataEncryptionParameters = new ChaCha20IETFPoly1305EncryptionParameters(dataKey);
        HeaderPacket headerPacket = new X25519ChaCha20IETFPoly1305HeaderPacket(this.dataEncryptionParameters, writerPrivateKey, readerPublicKey);
        List<HeaderPacket> headerPackets = Collections.singletonList(headerPacket);
        this.header = new Header(headerPackets);
        out.write(header.serialize());
    }

    /**
     * Constructs the Crypt4GHOutputStream by wrapping existing OutputStream with DataEditList included to a header.
     *
     * @param out              Existing OutputStream.
     * @param dataEditList     Data Edit List.
     * @param writerPrivateKey Sender's private key.
     * @param readerPublicKey  Recipient's public key.
     * @throws IOException              In case the Crypt4GH header can't be read from the underlying OutputStream.
     * @throws GeneralSecurityException In case the Crypt4GH header is malformed.
     */
    public Crypt4GHOutputStream(OutputStream out, DataEditList dataEditList, PrivateKey writerPrivateKey, PublicKey readerPublicKey) throws IOException, GeneralSecurityException {
        super(out);
        KeyUtils keyUtils = KeyUtils.getInstance();
        SecretKey dataKey = keyUtils.generateSessionKey();
        this.dataEncryptionParameters = new ChaCha20IETFPoly1305EncryptionParameters(dataKey);
        HeaderPacket dataEncryptionParametersHeaderPacket = new X25519ChaCha20IETFPoly1305HeaderPacket(this.dataEncryptionParameters, writerPrivateKey, readerPublicKey);
        HeaderPacket dataEditListHeaderPacket = new X25519ChaCha20IETFPoly1305HeaderPacket(dataEditList, writerPrivateKey, readerPublicKey);
        List<HeaderPacket> headerPackets = new ArrayList<>(List.of(dataEncryptionParametersHeaderPacket, dataEditListHeaderPacket));
        this.header = new Header(headerPackets);
        out.write(header.serialize());
    }

    /**
     * Gets header.
     *
     * @return Crypt4GH full header.
     */
    public Header getHeader() {
        return header;
    }

    /**
     * Writes a byte to an internal buffer and flushes this buffer when it get's full.
     *
     * @param b A byte to write.
     * @throws IOException In case the byte can't be written or the buffer can't be flushed.
     */
    @Override
    public void write(int b) throws IOException {
        if (bytesCached == buffer.length) {
            try {
                flushBuffer();
            } catch (GeneralSecurityException e) {
                throw new RuntimeException(e);
            }
        }
        buffer[bytesCached++] = (byte) b; // it's actually always `byte`, not `int`
    }

    protected void flushBuffer() throws IOException, GeneralSecurityException {
        Segment segment = Segment.create(Arrays.copyOfRange(buffer, 0, bytesCached), dataEncryptionParameters);
        out.write(segment.serialize());
        bytesCached = 0;
    }

    /**
     * Flushes the internal buffer before flushing the underlying stream.
     *
     * @throws IOException In case if the buffer or underlying stream can't be flushed.
     */
    @Override
    public void flush() throws IOException {
        try {
            flushBuffer();
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
        super.flush();
    }

}
