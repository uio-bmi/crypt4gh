package no.uio.ifi.crypt4gh.app;

import org.apache.commons.cli.*;

/**
 * Console application for encrypting/decrypting files.
 */
public class Main {

    public static final String GENERATE = "g";
    public static final String ENCRYPT = "e";
    public static final String DECRYPT = "d";
    public static final String PUBLIC_KEY = "pk";
    public static final String SECRET_KEY = "sk";
    public static final String VERSION = "v";
    public static final String HELP = "h";

    /**
     * Main method, entry-point to the application.
     *
     * @param args Command line arguments.
     */
    public static void main(String[] args) throws Exception {
        Options options = new Options();

        OptionGroup mainOptions = new OptionGroup();
        mainOptions.addOption(new Option(GENERATE, "generate", true, "generate key pair (specify desired key name)"));
        mainOptions.addOption(new Option(ENCRYPT, "encrypt", true, "encrypt the file (specify file to encrypt)"));
        mainOptions.addOption(new Option(DECRYPT, "decrypt", true, "decrypt the file (specify file to decrypt)"));
        mainOptions.addOption(new Option(VERSION, "version", false, "print application's version"));
        mainOptions.addOption(new Option(HELP, "help", false, "print this message"));
        options.addOptionGroup(mainOptions);

        options.addOption(new Option(PUBLIC_KEY, "pubkey", true, "public key to use (specify key file)"));
        options.addOption(new Option(SECRET_KEY, "seckey", true, "secret key to use (specify key file)"));

        CommandLineParser parser = new DefaultParser();
        Crypt4GHUtils crypt4GHUtils = Crypt4GHUtils.getInstance();
        try {
            CommandLine line = parser.parse(options, args);
            if (line.getOptions().length == 0) {
                printHelp(options);
                return;
            }
            if (line.hasOption(HELP)) {
                printHelp(options);
            } else if (line.hasOption(VERSION)) {
                printVersion();
            } else if (line.hasOption(GENERATE)) {
                crypt4GHUtils.generateX25519KeyPair(line.getOptionValue(GENERATE));
            } else {
                if (line.hasOption(ENCRYPT)) {
                    if (!line.hasOption(PUBLIC_KEY)) {
                        System.err.println("Missing argument for option: " + PUBLIC_KEY);
                        return;
                    }
                    if (!line.hasOption(SECRET_KEY)) {
                        System.err.println("Missing argument for option: " + SECRET_KEY);
                        return;
                    }
                    crypt4GHUtils.encryptFile(
                            line.getOptionValue(ENCRYPT),
                            line.getOptionValue(SECRET_KEY),
                            line.getOptionValue(PUBLIC_KEY)
                    );
                } else if (line.hasOption(DECRYPT)) {
                    if (!line.hasOption(SECRET_KEY)) {
                        System.err.println("Missing argument for option: " + SECRET_KEY);
                        return;
                    }
                    crypt4GHUtils.decryptFile(
                            line.getOptionValue(DECRYPT),
                            line.getOptionValue(SECRET_KEY)
                    );
                }
            }
        } catch (ParseException exp) {
            System.err.println(exp.getMessage());
        }
    }

    private static void printVersion() {
        String implementationVersion = Main.class.getPackage().getImplementationVersion();
        System.out.println("Crypt4GH " + implementationVersion);
    }

    private static void printHelp(Options options) {
        HelpFormatter formatter = new HelpFormatter();
        formatter.printHelp("crypt4gh",
                "\nCrypt4GH encryption/decryption tool\n\n",
                options,
                "\nRead more about the format at http://samtools.github.io/hts-specs/crypt4gh.pdf\n",
                true);
    }

}
