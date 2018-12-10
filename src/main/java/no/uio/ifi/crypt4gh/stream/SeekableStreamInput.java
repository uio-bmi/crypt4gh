package no.uio.ifi.crypt4gh.stream;

import htsjdk.samtools.seekablestream.SeekableStream;
import org.apache.commons.crypto.stream.input.StreamInput;

import java.io.IOException;
import java.io.InputStream;

/**
 * The <code>StreamInput/code> class takes a <code>InputStream</code> object and wraps it as
 * <code>Input</code> object acceptable by <code>CryptoInputStream</code>.
 * <p>
 * This implementation adds support for random access to underlying stream.
 */
public class SeekableStreamInput extends StreamInput {

    protected final SeekableStream seekableStream;
    protected final long dataStart;

    /**
     * Constructs a {@link StreamInput}.
     *
     * @param inputStream the inputstream object.
     * @param bufferSize  the buffersize.
     * @param dataStart   stream offset.
     * @throws IOException If inputStream is not instance of SeekableStream.
     */
    public SeekableStreamInput(InputStream inputStream, int bufferSize, long dataStart) throws IOException {
        super(inputStream, bufferSize);
        if (!(inputStream instanceof SeekableStream)) {
            throw new IOException(inputStream + " is not instance of SeekableStream");
        }
        this.seekableStream = (SeekableStream) inputStream;
        this.dataStart = dataStart;
    }

    /**
     * Returns stream length.
     *
     * @return Stream length.
     */
    public long length() {
        return seekableStream.length() - dataStart;
    }

    /**
     * Returns current position.
     *
     * @return Current position.
     * @throws IOException In case of IO error.
     */
    public long position() throws IOException {
        return seekableStream.position() - dataStart;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void seek(long position) throws IOException {
        seekableStream.seek(position + dataStart);
    }

    /**
     * Indicates end of file.
     *
     * @return <code>true</code> if stream reached its end, <code>false</code> otherwise.
     * @throws IOException In case of IO error.
     */
    public boolean eof() throws IOException {
        return seekableStream.eof();
    }

    /**
     * Returns <code>SeekableStream</code> source.
     *
     * @return String representation of source (e.g. URL, file path, etc.), or null if not available.
     */
    public String getSource() {
        return seekableStream.getSource();
    }

}
