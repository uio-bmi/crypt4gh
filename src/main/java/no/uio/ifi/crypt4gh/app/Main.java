package no.uio.ifi.crypt4gh.app;

import org.apache.commons.cli.*;

/**
 * Console application for encrypting/decrypting files.
 */
public class Main {

    public static final String GENERATE = "g";
    public static final String ENCRYPT = "e";
    public static final String DECRYPT = "d";
    public static final String HELP = "h";

    /**
     * Main method, entry-point to the application.
     *
     * @param args Command line arguments.
     */
    public static void main(String[] args) throws Exception {
        Options options = new Options();

        OptionGroup mainOptions = new OptionGroup();
        mainOptions.addOption(new Option(GENERATE, "generate", true, "generate PGP keypair (specify key ID)"));
        mainOptions.addOption(new Option(ENCRYPT, "encrypt", true, "encrypt the file (specify filename/filepath)"));
        mainOptions.addOption(new Option(DECRYPT, "decrypt", true, "decrypt the file (specify filename/filepath)"));
        mainOptions.addOption(new Option(HELP, "help", false, "print this message"));
        options.addOptionGroup(mainOptions);


        options.addOption(new Option("k", "key", true, "PGP key to use"));

        CommandLineParser parser = new DefaultParser();
        try {
            CommandLine line = parser.parse(options, args);
            if (line.hasOption(HELP)) {
                printHelp(options);
            } else if (line.hasOption(GENERATE)) {
                KeyUtils.getInstance().generatePGPKeyPair(line.getOptionValue(GENERATE));
            }
        } catch (ParseException exp) {
            System.err.println("Wrong syntax: " + exp.getMessage());
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
