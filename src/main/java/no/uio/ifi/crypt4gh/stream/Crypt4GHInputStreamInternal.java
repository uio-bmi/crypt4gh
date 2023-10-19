package no.uio.ifi.crypt4gh.stream;

import lombok.extern.slf4j.Slf4j;
import no.uio.ifi.crypt4gh.pojo.body.Segment;
import no.uio.ifi.crypt4gh.pojo.header.DataEditList;
import no.uio.ifi.crypt4gh.pojo.header.DataEncryptionParameters;
import no.uio.ifi.crypt4gh.pojo.header.Header;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.util.Arrays;
import java.util.Collection;
import java.util.Objects;
import java.util.Optional;

import static no.uio.ifi.crypt4gh.pojo.body.Segment.UNENCRYPTED_DATA_SEGMENT_SIZE;

/**
 * Internal part of Crypt4GHInputStream that wraps existing InputStream, not a public API.
 */
@Slf4j
class Crypt4GHInputStreamInternal extends FilterInputStream {

    private Header header;
    private int[] buffer;
    private int bytesRead;
    private Collection<DataEncryptionParameters> dataEncryptionParametersList;
    @SuppressWarnings("OptionalUsedAsFieldOrParameterType")
    private Optional<DataEditList> dataEditList;
    private int encryptedSegmentSize;
    private int lastDecryptedSegment = -1;

    /**
     * Constructs the internal part of Crypt4GHInputStream that wraps existing InputStream, not a public API.
     */
    Crypt4GHInputStreamInternal(InputStream in, PrivateKey readerPrivateKey) throws IOException, GeneralSecurityException {
        super(in);
        this.header = new Header(in, readerPrivateKey);
        this.dataEncryptionParametersList = header.getDataEncryptionParametersList();
        DataEncryptionParameters firstDataEncryptionParameters = dataEncryptionParametersList.iterator().next();
        for (DataEncryptionParameters encryptionParameters : dataEncryptionParametersList) {
            if (firstDataEncryptionParameters.getDataEncryptionMethod() != encryptionParameters.getDataEncryptionMethod()) {
                throw new GeneralSecurityException("Different Data Encryption Methods are not supported");
            }
        }
        this.encryptedSegmentSize = firstDataEncryptionParameters.getDataEncryptionMethod().getEncryptedSegmentSize();
        this.dataEditList = header.getDataEditList();
    }

    Optional<DataEditList> getDataEditList() {
        return dataEditList;
    }

    /**
     * Gets header.
     *
     * @return Crypt4GH full header.
     */
    Header getHeader() {
        return header;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public int read() throws IOException {
        if (buffer == null || buffer.length == bytesRead) {
            fillBuffer();
        }
        if (buffer == null || buffer.length == 0) {
            return -1;
        } else {
            return buffer[bytesRead++];
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public int read(byte[] b, int off, int len) throws IOException {
        /*
            Reusing default `InputStream`'s implementation, because `FilterStream`'s implementation doesn't fit
         */
        Objects.checkFromIndexSize(off, len, b.length);
        if (len == 0) {
            return 0;
        }

        int c = read();
        if (c == -1) {
            return -1;
        }
        b[off] = (byte) c;

        int i = 1;
        try {
            for (; i < len; i++) {
                c = read();
                if (c == -1) {
                    break;
                }
                b[off + i] = (byte) c;
            }
        } catch (IOException ee) {
            log.error(ee.getMessage(), ee);
        }
        return i;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public long skip(long n) throws IOException {
        if (n <= 0) {
            return 0;
        }
        if (buffer == null || buffer.length == bytesRead) {
            fillBuffer();
        }
        long currentDecryptedPosition = lastDecryptedSegment * UNENCRYPTED_DATA_SEGMENT_SIZE + bytesRead;
        long newDecryptedPosition = currentDecryptedPosition + n;
        long newSegmentNumber = newDecryptedPosition / UNENCRYPTED_DATA_SEGMENT_SIZE;
        if (newSegmentNumber != lastDecryptedSegment) {
            long segmentsToSkip = newSegmentNumber - lastDecryptedSegment - 1;
            skipSegments(segmentsToSkip);
            fillBuffer();
            currentDecryptedPosition = lastDecryptedSegment * UNENCRYPTED_DATA_SEGMENT_SIZE;
        }
        long delta = newDecryptedPosition - currentDecryptedPosition;
        if (bytesRead + delta > buffer.length) {
            long missingBytes = bytesRead + delta - buffer.length;
            bytesRead += (delta - missingBytes);
            return n - missingBytes;
        }
        bytesRead += delta;
        return n;
    }

    @SuppressWarnings("ResultOfMethodCallIgnored")
    private synchronized void skipSegments(long n) throws IOException {
        in.skip(n * encryptedSegmentSize);
        lastDecryptedSegment += n;
    }

    private synchronized void fillBuffer() throws IOException {
        try {
            byte[] encryptedSegmentBytes = in.readNBytes(encryptedSegmentSize);
            if (encryptedSegmentBytes.length > 0) {
                decryptSegment(encryptedSegmentBytes);
            } else if (buffer != null) {
                Arrays.fill(buffer, -1);
            }
            bytesRead = 0;
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    private synchronized void decryptSegment(byte[] encryptedSegmentBytes) throws GeneralSecurityException {
        Segment segment = Segment.create(encryptedSegmentBytes, dataEncryptionParametersList);
        byte[] unencryptedData = segment.getUnencryptedData();
        buffer = new int[unencryptedData.length];
        for (int i = 0; i < unencryptedData.length; i++) {
            buffer[i] = unencryptedData[i] & 0xff;
        }
        lastDecryptedSegment++;
    }

}
