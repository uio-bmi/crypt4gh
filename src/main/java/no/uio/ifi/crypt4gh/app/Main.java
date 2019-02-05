package no.uio.ifi.crypt4gh.app;

import org.apache.commons.cli.*;

import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Console application for encrypting/decrypting files.
 */
public class Main {

    public static final String GENERATE = "g";
    public static final String ENCRYPT = "e";
    public static final String DECRYPT = "d";
    public static final String HELP = "h";
    public static final String VERBOSE = "v";
    public static final String KEY = "k";

    /**
     * Main method, entry-point to the application.
     *
     * @param args Command line arguments.
     */
    public static void main(String[] args) throws Exception {
        Logger logger = Logger.getLogger("org.c02e.jpgpj");
        logger.setLevel(Level.OFF);

        Options options = new Options();

        OptionGroup mainOptions = new OptionGroup();
        mainOptions.addOption(new Option(GENERATE, "generate", true, "generate PGP keypair (specify key ID)"));
        mainOptions.addOption(new Option(ENCRYPT, "encrypt", true, "encrypt the file (specify filename/filepath)"));
        mainOptions.addOption(new Option(DECRYPT, "decrypt", true, "decrypt the file (specify filename/filepath)"));
        mainOptions.addOption(new Option(HELP, "help", false, "print this message"));
        options.addOptionGroup(mainOptions);

        options.addOption(new Option(KEY, "key", true, "PGP key to use"));
        options.addOption(new Option(VERBOSE, "verbose", false, "verbose mode"));

        CommandLineParser parser = new DefaultParser();
        try {
            CommandLine line = parser.parse(options, args);
            if (line.getOptions().length == 0) {
                printHelp(options);
                return;
            }
            if (line.hasOption(HELP)) {
                printHelp(options);
            } else if (line.hasOption(GENERATE)) {
                KeyUtils.getInstance().generatePGPKeyPair(line.getOptionValue(GENERATE));
            } else if (line.hasOption(ENCRYPT)) {
                if (!line.hasOption(KEY)) {
                    System.err.println("Missing argument for option: " + KEY);
                    return;
                }
                Crypt4GHUtils.getInstance().encryptFile(line.getOptionValue(ENCRYPT),
                        line.getOptionValue(KEY),
                        line.hasOption(VERBOSE));
            } else if (line.hasOption(DECRYPT)) {
                if (!line.hasOption(KEY)) {
                    System.err.println("Missing argument for option: " + KEY);
                    return;
                }
                Crypt4GHUtils.getInstance().decryptFile(line.getOptionValue(DECRYPT),
                        line.getOptionValue(KEY),
                        line.hasOption(VERBOSE));
            }
        } catch (ParseException exp) {
            System.err.println(exp.getMessage());
        }
    }

    private static void printHelp(Options options) {
        HelpFormatter formatter = new HelpFormatter();
        formatter.printHelp("crypt4gh",
                "\nCrypt4GH encryption/decryption tool\n\n",
                options,
                "\nRead more about the format at http://bit.ly/crypt4gh\n",
                true);
    }

}
