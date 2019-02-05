package no.uio.ifi.crypt4gh.app;

import org.apache.commons.io.FileUtils;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.sig.Features;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyEncryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyPair;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.attribute.PosixFilePermission;
import java.security.SecureRandom;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;

public class KeyUtils {

    private static KeyUtils ourInstance = new KeyUtils();

    public static KeyUtils getInstance() {
        return ourInstance;
    }


    private KeyUtils() {
    }

    public void generatePGPKeyPair(String keyId) throws Exception {
        char[] passphrase = System.console().readPassword("Enter the passphrase to lock the secret key: ");
        PGPKeyRingGenerator generator = createPGPKeyRingGenerator(keyId, passphrase);

        PGPPublicKeyRing pkr = generator.generatePublicKeyRing();
        ByteArrayOutputStream pubOut = new ByteArrayOutputStream();
        pkr.encode(pubOut);
        pubOut.close();

        PGPSecretKeyRing skr = generator.generateSecretKeyRing();
        ByteArrayOutputStream secOut = new ByteArrayOutputStream();
        skr.encode(secOut);
        secOut.close();

        byte[] armoredPublicBytes = armorByteArray(pubOut.toByteArray());
        byte[] armoredSecretBytes = armorByteArray(secOut.toByteArray());

        ConsoleUtils consoleUtils = ConsoleUtils.getInstance();
        File pubFile = new File(keyId + ".pub.asc");
        System.out.println(pubFile.getAbsolutePath());
        if (!pubFile.exists() || pubFile.exists() &&
                consoleUtils.promptForConfirmation("Public key file already exists: do you want to overwrite it?")) {
            FileUtils.write(pubFile, new String(armoredPublicBytes), Charset.defaultCharset());
        }
        File secFile = new File(keyId + ".sec.asc");
        if (!secFile.exists() || secFile.exists() &&
                consoleUtils.promptForConfirmation("Private key file already exists: do you want to overwrite it?")) {
            FileUtils.write(secFile, new String(armoredSecretBytes), Charset.defaultCharset());
            Set<PosixFilePermission> perms = new HashSet<>();
            perms.add(PosixFilePermission.OWNER_READ);
            perms.add(PosixFilePermission.OWNER_WRITE);
            Files.setPosixFilePermissions(secFile.toPath(), perms);
        }
    }

    private PGPKeyRingGenerator createPGPKeyRingGenerator(String keyId, char[] passphrase) throws Exception {
        RSAKeyPairGenerator keyPairGenerator = new RSAKeyPairGenerator();

        keyPairGenerator.init(
                new RSAKeyGenerationParameters(BigInteger.valueOf(0x10001), new SecureRandom(), 4096,
                        12));

        PGPKeyPair rsaKeyPair =
                new BcPGPKeyPair(PGPPublicKey.RSA_GENERAL, keyPairGenerator.generateKeyPair(),
                        new Date());

        PGPSignatureSubpacketGenerator signHashGenerator = new PGPSignatureSubpacketGenerator();
        signHashGenerator.setKeyFlags(false, KeyFlags.SIGN_DATA | KeyFlags.CERTIFY_OTHER);
        signHashGenerator.setFeature(false, Features.FEATURE_MODIFICATION_DETECTION);

        PGPSignatureSubpacketGenerator encryptHashGenerator = new PGPSignatureSubpacketGenerator();
        encryptHashGenerator.setKeyFlags(false, KeyFlags.ENCRYPT_COMMS | KeyFlags.ENCRYPT_STORAGE);

        PGPDigestCalculator sha1DigestCalculator =
                new BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA1);
        PGPDigestCalculator sha512DigestCalculator =
                new BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA512);

        PBESecretKeyEncryptor secretKeyEncryptor =
                (new BcPBESecretKeyEncryptorBuilder(PGPEncryptedData.AES_256, sha512DigestCalculator))
                        .build(passphrase);

        return new PGPKeyRingGenerator(PGPSignature.NO_CERTIFICATION, rsaKeyPair, keyId,
                sha1DigestCalculator, encryptHashGenerator.generate(), null,
                new BcPGPContentSignerBuilder(rsaKeyPair.getPublicKey().getAlgorithm(),
                        HashAlgorithmTags.SHA512), secretKeyEncryptor);
    }

    private byte[] armorByteArray(byte[] data) throws IOException {
        ByteArrayOutputStream encOut = new ByteArrayOutputStream();
        ArmoredOutputStream armorOut = new ArmoredOutputStream(encOut);
        armorOut.write(data);
        armorOut.flush();
        armorOut.close();
        return encOut.toByteArray();
    }

}
