package no.uio.ifi.crypt4gh.app;

import htsjdk.samtools.seekablestream.SeekableFileStream;
import no.uio.ifi.crypt4gh.stream.Crypt4GHInputStream;
import no.uio.ifi.crypt4gh.stream.Crypt4GHOutputStream;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.jcajce.provider.util.BadBlockException;
import org.bouncycastle.openpgp.PGPException;
import org.c02e.jpgpj.PassphraseException;

import java.io.*;
import java.nio.charset.Charset;

public class Crypt4GHUtils {

    private static Crypt4GHUtils ourInstance = new Crypt4GHUtils();

    public static Crypt4GHUtils getInstance() {
        return ourInstance;
    }

    private Crypt4GHUtils() {
    }

    public void encryptFile(String dataFilePath, String keyFilePath, boolean verbose) throws IOException, PGPException {
        File dataInFile = new File(dataFilePath);
        File dataOutFile = new File(dataFilePath + ".enc");
        if (dataOutFile.exists() && !ConsoleUtils.getInstance().promptForConfirmation(dataOutFile.getAbsolutePath() + " already exists. Overwrite?")) {
            return;
        }
        String key = FileUtils.readFileToString(new File(keyFilePath), Charset.defaultCharset());
        byte[] digest;
        try (InputStream inputStream = new FileInputStream(dataInFile)) {
            digest = DigestUtils.sha256(inputStream);
        }

        try (InputStream inputStream = new FileInputStream(dataInFile);
             OutputStream outputStream = new FileOutputStream(dataOutFile);
             Crypt4GHOutputStream crypt4GHOutputStream = new Crypt4GHOutputStream(outputStream, key, digest)) {
            if (verbose) {
                String sessionKey = Hex.encodeHexString(crypt4GHOutputStream.getSessionKeyBytes());
                String iv = Hex.encodeHexString(crypt4GHOutputStream.getIvBytes());
                System.out.println("AES session key: " + sessionKey);
                System.out.println("AES IV: " + iv);
            }
            System.out.println("Encryption initialized...");
            IOUtils.copyLarge(inputStream, crypt4GHOutputStream);
            System.out.println("Done: " + dataOutFile.getAbsolutePath());
        }
    }

    public void decryptFile(String dataFilePath, String keyFilePath, boolean verbose) throws IOException, PGPException, BadBlockException {
        File dataInFile = new File(dataFilePath);
        File dataOutFile = new File(dataFilePath + ".dec");
        if (dataOutFile.exists() && !ConsoleUtils.getInstance().promptForConfirmation(dataOutFile.getAbsolutePath() + " already exists. Overwrite?")) {
            return;
        }
        String key = FileUtils.readFileToString(new File(keyFilePath), Charset.defaultCharset());
        char[] passphrase = System.console().readPassword("Enter the passphrase to unlock the secret key: ");
        try (SeekableFileStream inputStream = new SeekableFileStream(dataInFile);
             OutputStream outputStream = new FileOutputStream(dataOutFile);
             Crypt4GHInputStream crypt4GHInputStream = new Crypt4GHInputStream(inputStream, key, passphrase)) {
            System.out.println("Decryption initialized...");
            IOUtils.copyLarge(crypt4GHInputStream, outputStream);
            System.out.println("Done: " + dataOutFile.getAbsolutePath());
        } catch (PassphraseException e) {
            System.err.println(e.getMessage());
            dataOutFile.delete();
        }
    }

}
