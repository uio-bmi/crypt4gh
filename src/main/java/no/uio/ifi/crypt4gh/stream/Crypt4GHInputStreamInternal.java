package no.uio.ifi.crypt4gh.stream;

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
class Crypt4GHInputStreamInternal extends FilterInputStream {

    private int[] buffer;
    private int bytesRead;
    private Collection<DataEncryptionParameters> dataEncryptionParametersList;
    private Optional<DataEditList> dataEditList;
    private int encryptedSegmentSize;
    private int lastDecryptedSegment = -1;

    /**
     * Constructs the internal part of Crypt4GHInputStream that wraps existing InputStream, not a public API.
     */
    Crypt4GHInputStreamInternal(InputStream in, PrivateKey readerPrivateKey) throws IOException, GeneralSecurityException {
        super(in);
        Header header = new Header(in, readerPrivateKey);
        this.dataEncryptionParametersList = header.getDataEncryptionParametersList();
        if (dataEncryptionParametersList.isEmpty()) {
            throw new GeneralSecurityException("Data Encryption Parameters not found in the Header");
        }
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
     * {@inheritDoc}
     */
    @Override
    public int read() throws IOException {
        if (buffer == null || buffer.length == bytesRead) {
            fillBuffer();
        }
        return buffer[bytesRead++];
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

    private synchronized void skipSegments(long n) throws IOException {
        in.skip(n * encryptedSegmentSize);
        lastDecryptedSegment += n;
    }

    private synchronized void fillBuffer() throws IOException {
        try {
            byte[] encryptedSegmentBytes = in.readNBytes(encryptedSegmentSize);
            if (encryptedSegmentBytes.length == 0) {
                Arrays.fill(buffer, (byte) (-1));
            } else {
                decryptSegment(encryptedSegmentBytes);
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
        }
        return i;
    }

}
