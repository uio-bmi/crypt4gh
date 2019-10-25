package no.uio.ifi.crypt4gh.app;

import java.io.Console;

/**
 * Console utility class, not a public API.
 */
class ConsoleUtils {

    private static ConsoleUtils ourInstance = new ConsoleUtils();

    static ConsoleUtils getInstance() {
        return ourInstance;
    }

    private ConsoleUtils() {
    }

    boolean promptForConfirmation(String prompt) {
        Console console = System.console();
        Boolean confirm = null;
        while (confirm == null) {
            String response = console.readLine(prompt + " (y/n) ");
            if (response.toLowerCase().startsWith("y")) {
                confirm = true;
            } else if (response.toLowerCase().startsWith("n")) {
                confirm = false;
            }
        }
        return confirm;
    }

    char[] readPassword(String prompt, int minLength) {
        while (true) {
            char[] password = System.console().readPassword(prompt);
            if (password.length >= minLength) {
                return password;
            } else {
                System.out.println("Passphrase is too short: min length is " + minLength);
            }
        }
    }

}
