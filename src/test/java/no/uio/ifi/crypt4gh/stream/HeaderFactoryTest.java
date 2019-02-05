package no.uio.ifi.crypt4gh.stream;

import htsjdk.samtools.seekablestream.SeekableFileStream;
import htsjdk.samtools.seekablestream.SeekableStream;
import no.uio.ifi.crypt4gh.factory.HeaderFactory;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.io.File;
import java.util.Collection;

@RunWith(JUnit4.class)
public class HeaderFactoryTest {

    @Test
    public void getKeyIdsTest() throws Exception {
        SeekableStream seekableStream = new SeekableFileStream(new File(getClass().getClassLoader().getResource("sample.txt.enc").getFile()));
        int headerLength = HeaderFactory.UNENCRYPTED_HEADER_LENGTH + 645;
        byte[] headerBytes = new byte[headerLength];
        seekableStream.read(headerBytes, 0, headerLength);
        Collection<String> keyIds = HeaderFactory.getInstance().getKeyIds(headerBytes);
        Assert.assertNotNull(keyIds);
        Assert.assertEquals(1, keyIds.size());
        Assert.assertEquals("130560167a9315f9", keyIds.iterator().next());
    }

}
