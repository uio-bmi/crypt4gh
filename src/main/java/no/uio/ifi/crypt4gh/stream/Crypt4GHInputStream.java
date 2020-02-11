package no.uio.ifi.crypt4gh.stream;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.ToString;
import lombok.extern.slf4j.Slf4j;
import no.uio.ifi.crypt4gh.pojo.header.DataEditList;
import no.uio.ifi.crypt4gh.pojo.header.Header;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.util.ArrayDeque;
import java.util.Objects;
import java.util.Optional;
import java.util.Queue;

/**
 * Crypt4GHInputStream that wraps existing InputStream.
 */
@Slf4j
public class Crypt4GHInputStream extends FilterInputStream {

    private boolean useDataEditList;
    private Queue<DataEditListEntry> lengths = new ArrayDeque<>();
    private long bytesRead;

    /**
     * Constructs Crypt4GHInputStream that wraps existing InputStream.
     *
     * @param in               Existing InputStream.
     * @param readerPrivateKey Recipient's private key.
     * @throws IOException              In case the Crypt4GH header can't be read from the underlying InputStream.
     * @throws GeneralSecurityException In case the Crypt4GH header can't be deserialized.
     */
    public Crypt4GHInputStream(InputStream in, PrivateKey readerPrivateKey) throws IOException, GeneralSecurityException {
        super(new Crypt4GHInputStreamInternal(in, readerPrivateKey));
        Optional<DataEditList> dataEditListOptional = ((Crypt4GHInputStreamInternal) this.in).getDataEditList();
        this.useDataEditList = dataEditListOptional.isPresent();
        long[] lengthsArray = dataEditListOptional.map(DataEditList::getLengths).orElse(new long[]{});
        boolean skip = true;
        for (long length : lengthsArray) {
            lengths.add(new DataEditListEntry(length, skip));
            skip = !skip;
        }
    }

    /**
     * Constructs Crypt4GHInputStream that wraps existing InputStream with DataEditList.
     *
     * @param in               Existing InputStream.
     * @param dataEditList     DataEditList
     * @param readerPrivateKey Recipient's private key.
     * @throws IOException              In case the Crypt4GH header can't be read from the underlying InputStream.
     * @throws GeneralSecurityException In case the Crypt4GH header can't be deserialized.
     */
    public Crypt4GHInputStream(InputStream in, DataEditList dataEditList, PrivateKey readerPrivateKey) throws IOException, GeneralSecurityException {
        super(new Crypt4GHInputStreamInternal(in, readerPrivateKey));
        this.useDataEditList = true;
        long[] lengthsArray = dataEditList.getLengths();
        boolean skip = true;
        for (long length : lengthsArray) {
            this.lengths.add(new DataEditListEntry(length, skip));
            skip = !skip;
        }
    }

    /**
     * Gets header.
     *
     * @return Crypt4GH full header.
     */
    public Header getHeader() {
        return ((Crypt4GHInputStreamInternal) in).getHeader();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public int read() throws IOException {
        return useDataEditList ? readWithDataEditList() : in.read();
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

    private synchronized int readWithDataEditList() throws IOException {
        if (!lengths.isEmpty()) {
            DataEditListEntry dataEditListEntry = lengths.peek();
            if (dataEditListEntry.skip) {
                in.skip(dataEditListEntry.length);
                lengths.remove();
            }
        }
        if (!lengths.isEmpty()) {
            DataEditListEntry dataEditListEntry = lengths.peek();
            long length = dataEditListEntry.length;
            if (bytesRead == length) {
                lengths.remove();
                bytesRead = 0;
                return readWithDataEditList();
            } else {
                bytesRead++;
                return in.read();
            }
        }
        return -1;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public long skip(long n) throws IOException {
        return useDataEditList ? skipWithDataEditList(n) : in.skip(n);
    }

    private synchronized long skipWithDataEditList(long n) throws IOException {
        long bytesSkipped = 0;
        if (!lengths.isEmpty()) {
            DataEditListEntry dataEditListEntry = lengths.peek();
            if (dataEditListEntry.skip) {
                in.skip(dataEditListEntry.length);
                lengths.remove();
            } else {
                long length = dataEditListEntry.length;
                if (bytesRead == length) {
                    lengths.remove();
                    bytesRead = 0;
                } else {
                    long bytesLeftToRead = length - bytesRead;
                    if (n <= bytesLeftToRead) {
                        bytesRead += n;
                        return in.skip(n);
                    } else {
                        bytesSkipped += in.skip(bytesLeftToRead);
                        n -= bytesLeftToRead;
                        lengths.remove();
                        bytesRead = 0;
                    }
                }
            }
        }
        while (!lengths.isEmpty() && n != 0) {
            DataEditListEntry dataEditListEntry = lengths.peek();
            if (dataEditListEntry.skip) {
                in.skip(dataEditListEntry.length);
                lengths.remove();
            } else {
                long length = dataEditListEntry.length;
                if (n <= length) {
                    long bytesSkippedJustNow = in.skip(n);
                    bytesRead += bytesSkippedJustNow;
                    bytesSkipped += bytesSkippedJustNow;
                    return bytesSkipped;
                } else {
                    bytesSkipped += in.skip(length);
                    n -= length;
                    lengths.remove();
                }
            }
        }
        return bytesSkipped;
    }

    @ToString
    @AllArgsConstructor
    @Data
    private static class DataEditListEntry {

        private long length;
        private boolean skip;

    }

}
