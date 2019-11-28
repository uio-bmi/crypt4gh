package no.uio.ifi.crypt4gh.app;

import no.uio.ifi.crypt4gh.pojo.key.Format;
import no.uio.ifi.crypt4gh.stream.Crypt4GHInputStream;
import no.uio.ifi.crypt4gh.stream.Crypt4GHOutputStream;
import no.uio.ifi.crypt4gh.util.KeyUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.attribute.PosixFilePermission;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.HashSet;
import java.util.Set;

/**
 * Encryption/decryption utility class, not a public API.
 */
class Crypt4GHUtils {

    private static Crypt4GHUtils ourInstance = new Crypt4GHUtils();

    static Crypt4GHUtils getInstance() {
        return ourInstance;
    }

    private KeyUtils keyUtils = KeyUtils.getInstance();
    private ConsoleUtils consoleUtils = ConsoleUtils.getInstance();

    private Crypt4GHUtils() {
    }

    void generateX25519KeyPair(String keyName, String keyFormat, String keyPassword) throws Exception {
        KeyUtils keyUtils = KeyUtils.getInstance();
        KeyPair keyPair = keyUtils.generateKeyPair();
        File pubFile = new File(keyName + ".pub.pem");
        if (!pubFile.exists() || pubFile.exists() &&
                consoleUtils.promptForConfirmation("Public key file already exists: do you want to overwrite it?")) {
            if (Format.CRYPT4GH.name().equalsIgnoreCase(keyFormat)) {
                keyUtils.writeCrypt4GHKey(pubFile, keyPair.getPublic(), null);
            } else {
                keyUtils.writeOpenSSLKey(pubFile, keyPair.getPublic());
            }
        }
        File secFile = new File(keyName + ".sec.pem");
        if (!secFile.exists() || secFile.exists() &&
                consoleUtils.promptForConfirmation("Private key file already exists: do you want to overwrite it?")) {
            if (Format.CRYPT4GH.name().equalsIgnoreCase(keyFormat)) {
                char[] password;
                if (StringUtils.isEmpty(keyPassword)) {
                    password = consoleUtils.readPassword("Password for the private key: ", 4);
                } else {
                    if (keyPassword.length() < 4) {
                        password = consoleUtils.readPassword("Password for the private key: ", 4);
                    } else {
                        password = keyPassword.toCharArray();
                    }
                }
                keyUtils.writeCrypt4GHKey(secFile, keyPair.getPrivate(), password);
            } else {
                keyUtils.writeOpenSSLKey(secFile, keyPair.getPrivate());
            }
        }
        Set<PosixFilePermission> perms = new HashSet<>();
        perms.add(PosixFilePermission.OWNER_READ);
        perms.add(PosixFilePermission.OWNER_WRITE);
        Files.setPosixFilePermissions(secFile.toPath(), perms);
    }

    void encryptFile(String dataFilePath, String privateKeyFilePath, String publicKeyFilePath) throws IOException, GeneralSecurityException {
        File dataInFile = new File(dataFilePath);
        File dataOutFile = new File(dataFilePath + ".enc");
        if (dataOutFile.exists() && !ConsoleUtils.getInstance().promptForConfirmation(dataOutFile.getAbsolutePath() + " already exists. Overwrite?")) {
            return;
        }
        PrivateKey privateKey = readPrivateKey(privateKeyFilePath);
        PublicKey publicKey = keyUtils.readPublicKey(new File(publicKeyFilePath));
        try (InputStream inputStream = new FileInputStream(dataInFile);
             OutputStream outputStream = new FileOutputStream(dataOutFile);
             Crypt4GHOutputStream crypt4GHOutputStream = new Crypt4GHOutputStream(outputStream, privateKey, publicKey)) {
            System.out.println("Encryption initialized...");
            IOUtils.copyLarge(inputStream, crypt4GHOutputStream);
            System.out.println("Done: " + dataOutFile.getAbsolutePath());
        } catch (GeneralSecurityException e) {
            System.err.println(e.getMessage());
            dataOutFile.delete();
        }
    }

    void decryptFile(String dataFilePath, String privateKeyFilePath) throws IOException, GeneralSecurityException {
        File dataInFile = new File(dataFilePath);
        File dataOutFile = new File(dataFilePath + ".dec");
        if (dataOutFile.exists() && !ConsoleUtils.getInstance().promptForConfirmation(dataOutFile.getAbsolutePath() + " already exists. Overwrite?")) {
            return;
        }
        PrivateKey privateKey = readPrivateKey(privateKeyFilePath);
        System.out.println("Decryption initialized...");
        try (FileInputStream inputStream = new FileInputStream(dataInFile);
             OutputStream outputStream = new FileOutputStream(dataOutFile);
             Crypt4GHInputStream crypt4GHInputStream = new Crypt4GHInputStream(inputStream, privateKey)) {
            IOUtils.copyLarge(crypt4GHInputStream, outputStream);
            System.out.println("Done: " + dataOutFile.getAbsolutePath());
        } catch (GeneralSecurityException e) {
            System.err.println(e.getMessage());
            dataOutFile.delete();
        }
    }

    private PrivateKey readPrivateKey(String privateKeyFilePath) throws IOException, GeneralSecurityException {
        PrivateKey privateKey;
        try {
            privateKey = keyUtils.readPrivateKey(new File(privateKeyFilePath), null);
        } catch (IllegalArgumentException e) {
            char[] password = consoleUtils.readPassword("Password for the private key: ", 4);
            privateKey = keyUtils.readPrivateKey(new File(privateKeyFilePath), password);
        }
        return privateKey;
    }

}
