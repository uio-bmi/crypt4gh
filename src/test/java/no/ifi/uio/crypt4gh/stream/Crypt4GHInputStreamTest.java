package no.ifi.uio.crypt4gh.stream;

import htsjdk.samtools.seekablestream.SeekableFileStream;
import htsjdk.samtools.seekablestream.SeekableStream;
import org.apache.commons.io.IOUtils;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.Charset;
import java.util.List;

@RunWith(JUnit4.class)
public class Crypt4GHInputStreamTest {

    @Test(expected = IOException.class)
    public void tooSmallBuffer() throws Exception {
        SeekableStream seekableStream = new SeekableFileStream(new File(getClass().getClassLoader().getResource("sample.txt.enc").getFile()));
        new Crypt4GHInputStream(seekableStream, getKey(), getPassphrase(), 500);
    }

    @Test
    public void decryptWhole() throws Exception {
        List<String> rawContents = IOUtils.readLines(getClass().getClassLoader().getResource("sample.txt").openStream(), Charset.defaultCharset());

        SeekableStream seekableStream = new SeekableFileStream(new File(getClass().getClassLoader().getResource("sample.txt.enc").getFile()));
        Crypt4GHInputStream crypt4GHInputStream = new Crypt4GHInputStream(seekableStream, getKey(), getPassphrase(), 600);

        List<String> lines = IOUtils.readLines(crypt4GHInputStream, Charset.defaultCharset());
        Assert.assertEquals(rawContents, lines);

        crypt4GHInputStream.close();
    }

    @Test
    public void decryptPart() throws Exception {
        List<String> rawContents = IOUtils.readLines(getClass().getClassLoader().getResource("sample.txt").openStream(), Charset.defaultCharset());

        SeekableStream seekableStream = new SeekableFileStream(new File(getClass().getClassLoader().getResource("sample.txt.enc").getFile()));
        Crypt4GHInputStream crypt4GHInputStream = new Crypt4GHInputStream(seekableStream, getKey(), getPassphrase());

        crypt4GHInputStream.seek(42);
        String line = new String(IOUtils.readFully(crypt4GHInputStream, 36));
        Assert.assertEquals(rawContents.get(1), line);

        crypt4GHInputStream.seek(0);
        line = new String(IOUtils.readFully(crypt4GHInputStream, 41));
        Assert.assertEquals(rawContents.get(0), line);

        crypt4GHInputStream.close();
    }

    @Test
    public void reencryption() throws Exception {
        SeekableStream seekableStream = new SeekableFileStream(new File(getClass().getClassLoader().getResource("sample.txt.enc").getFile()));
        Crypt4GHInputStream crypt4GHInputStream = new Crypt4GHInputStream(seekableStream, getKey(), getPassphrase());

        File tempFile = new File("output.enc");
        OutputStream outputStream = new FileOutputStream(tempFile);
        Crypt4GHOutputStream crypt4GHOutputStream = new Crypt4GHOutputStream(outputStream, getKey());
        IOUtils.copyLarge(crypt4GHInputStream, crypt4GHOutputStream);

        crypt4GHInputStream.close();
        outputStream.close();
        outputStream.flush();
        tempFile.delete();
    }

    private String getKey() {
        return "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
                "Version: PGPy v0.4.3\n" +
                "\n" +
                "xcaGBFsH1xkBEACVpuolwCIh62QcfZWdTZxIQh+wCSEOGb3THeao4ulRB5s/H8Yk\n" +
                "empqraNnDvJeYq4JebJ5MmgCdv/RVmmr4hw6+a7Kw9xLp0K7eQe0XjnwgZ2KL4Ry\n" +
                "ZO11okOLrlLmw3uG5e3R8oszIgQKb95d1oU3b97CifTw6+Kg4/KaEpgNsMmdpKwC\n" +
                "z3a3Dk+jcJVaKpoQ7OIOE9TqbAGKS8Ct4tcu6VnVbgZVATaoxYX6gy76VFiviNhU\n" +
                "2kEKdKdQbL3D/mRpfZPHV0SWl1+hZ9BpvwDHp7iFB5rtaIYzsFHByRhPHVTeRsxa\n" +
                "z43uavv8PhaDR5ssszWJlPm4a6V4yV57tCYxBYmLEmFlCR/603VSgk3TlUWgjabC\n" +
                "JJwu4vtSJs8wMi4yCFpbLz9+1q/PL7hWyaQU9TI4WlBw1CxGMyC+JyOE70zgJPFm\n" +
                "cdlPZAL2TmK/2T+LKx7E4rLhtwcLMMyKVDxtu3geWcW1E0aNlgHG1xpStvMb7+Sh\n" +
                "0xTX2VxTJZ6hLulJOjnYiljXdU+Oc3n7YcCzrCBF9DF7kKwLKZpg6Dm0Lg0xVITE\n" +
                "kQj432gTZCiqv9sB4RSeR4Z5qrnSWqAc+e15+VJgw4AXfzf37AyBIU29nxRuANye\n" +
                "tKgHj3Ndju2VRxEf07v0+tCsrXcXuii8c88YcYq5RFsQzEmvfv2YjneCGwARAQAB\n" +
                "/gkDCBeEgmQph3oR9jQG7ALRg+/0nDOyJf/aHi46wQmM/VcWwf4lThsYkF0Xu4YH\n" +
                "WpZeQ33IHuL1KNAHgL9ja8mX+/HiHfJv9oMhhf80vi/b7TFT2shJ4dQvqxxSbZjb\n" +
                "AYgPWklqJFWzPlUFJEXq3cXpYEwbePke5FSn2C3Glw8HVb7aM72s2pIBQ89zNNXF\n" +
                "QONh+w9ZVFL2igSUE5LXrDC8wKKDmi5cfkr8CScjHUJrPthzujEV9fr2j6Vy0bkF\n" +
                "tHXjYBwSw+pnsBLSiVPNpNvF30Pgsesnh9tqWOiFmIbNxPHmn0d9ChZlbA2wy1X5\n" +
                "HqHzjFFxoWf6utfPtB4LkbD7ioBc1KCU+HVQssBID7vQNa23qKJmfzMB7ZMfkYyo\n" +
                "J7cfdqbI/gmqMngXvWhjkr61CRdIbEDyZB1h0cxFBwSoiFdt5WxPdpQVyZvDXFot\n" +
                "nuKqwjqa7/qIiaRV4koyJ+xhOkStkpC/KSxK+HM3iZPdOxn9I8jj8ffrKrZyEHuf\n" +
                "VkMp7KRYUfn7TJKia/jcOFAAhckGmn2x2FBJj/JA0KUJafjS/7GDOxL4Cc6ww5uI\n" +
                "cSttgEhRxv3bVazA1kYVTbzI5a0fsqu64WD5g/UJeiFIfPIzGNO2269NTr16MmGi\n" +
                "kHPz6RHpMQ7GCbugtxIkRZX1Hnk1kYV7nlSYLmuT1joFv1cIaQUGFQPVoQUgdGEr\n" +
                "eevgyfrXe/LTr6UTdikSDmsbb1DK/4KKT1iDYmZ4dJk/N3E2trbGTTMqINNOza9U\n" +
                "Tg8PMHZpZmeSr29ngFcHIPVnX2bLD8r7pEOOTGe7E9ieLZ/kbk5GUIsTJFQzznyO\n" +
                "7FNvCimJfJPlJc/EkpE/r921rFRwGvh0asPwYC8aU+9hUcYUzMeUidKsvsNF7qkn\n" +
                "Eu85kH3Pprf6g27ZPD8Ow4COLkjVzTDYkcf5PAhuw2caZaBuJcOSdJHyP7toxCvi\n" +
                "Ivcp4PAR/OdLnJfr7eDVVgy7YHw1+PI1rQxf2Kw5ZKj6LLmoPV9zEbM36HyeEvbK\n" +
                "tbMQzf7XIUoIJJo+c0S1WMmWWKmJ207c5ELhSuFwJjw8rDsDTMqaevnwI7kFpuNj\n" +
                "KaOKW3i6+aJ1DwCY6Qc6i022cmcKXduunPgpKmoan7M7Z800BeRLbqrXlsQXi0qW\n" +
                "GVUM0VB4cNbZdo0229CFq0L0MJPe2e8antlIdBTNV9k8lA/v8m0IiX4rTyMvU0FY\n" +
                "QPSu4byhX96fpFocE6w1Y22alRjyLoEWR9TEoq0bb/5XuNCd3jcdcnqmEBV+c9Aq\n" +
                "C3pxeVANnjnlv3bec23u/mUIWAa5FkHEJpKpDzLubthlmuIwo7eykzXxmLRMpieM\n" +
                "XrTrnzwIzSM3U/R1Da+L34cJG/RaYgZylzZJAd6FTrb9bGCqJMhrNuwi1euLoKzV\n" +
                "OISxImc9dbyEfUvPwqwS/01qpODn6vdyCNvNlRUwcPhOn2NmeTZe7l5xmG+RaaWy\n" +
                "diQmTbUp/4FGsoiP2GEbLZTlxMnCVnWwKJH/9etGPVyo+SO4a6RpJYXTmU0X8/qA\n" +
                "h+tx+xFpBgCX4YXeKnB8rUuKz55OiC/LwTsDfOtIHkeMxSYjCv64yMomLUdBVNPi\n" +
                "t10HUD0Dmc/6tIQlCluGA7U8DxF/40DVPLQhJQSTcsA1A4a7l33KE68/rpQub8q9\n" +
                "uy8kRYbaoWnSXcBed6KuqRaCiMXEPiwyTCZxxpQDjb82kGEPeakuiKer/ETr8HLr\n" +
                "YAv2RAeMT84M+eZzlmGxdvahnOtUN5nObcSVjMUrxMV7LqNnyHnRB53NIEVHQSBT\n" +
                "d2VkZW4gKEBOQklTKSA8ZWdhQG5iaXMuc2U+wsFzBBMBCAAdBQJbB9cZAhsOBAsJ\n" +
                "CAcFFQgJCgsFFgIDAQACHgEACgkQEwVgFnqTFfkKWA//Rl6YTTdVKnhByvDwpWLK\n" +
                "bQOjleY5fUV+LnMDUBT6eKidkGCIS0QraV8b1LQbd2sXUkHn5Aw5ifarqyE7ob4s\n" +
                "OmEnpy2jgr3fz+IVr9xi1SvhOCm0mz4VFnsCzV33Y23vZDlnAx5xws3eEnRXz7cu\n" +
                "EFqFKUxL4CRJh4i56iP4UQNw98IS3KQEhEEK6cn7YJQHBLsX3qte4ISoO5yORSB9\n" +
                "0zRLXcydj2fqKZl3A9BAro/t8RNfvxbycIFoe/6e5xcFKJ3zqp6c0W5leNbD9PV7\n" +
                "BPphiGY6+JCjniG0dUD+XF8Y2B/i2HdNjorTX1hOr2lCFzkpXl+8nP/k7qdEYZHL\n" +
                "3n/8uZ/ol5VsaPCALBfjL7rGen6H7MP/lO+wECUfC6omnfo7ZmEr9UqzhvTt10IV\n" +
                "LQUYx6MP3aKGHiV1rdlwW6UiOdmrdGV4LOgwCxU3Ugno+kha65EfaN2Q296MZgkF\n" +
                "VWUpuAc15yJFt5H0/QNAULWpylVZ2h6AxdWgz9w3ppnCNO3K8NOUI8GWjC2XxHBj\n" +
                "8U2g15730Oinh42cAVz3VmlXC6h38qF/3CQjiW+kJsqlBIQZxHj68E/AjvPAFycX\n" +
                "4fAZ/0a8bRvrHL/q7rT2HU8RAZeC57GyZVpJVTENOijAO536PEhSDrTHUZSJ05gr\n" +
                "qPMEpLMxGstrdJNx4f3PYtE=\n" +
                "=0PNs\n" +
                "-----END PGP PRIVATE KEY BLOCK-----\n";
    }

    private String getPassphrase() {
        return "fgpJuRRWZohCewVc";
    }

}