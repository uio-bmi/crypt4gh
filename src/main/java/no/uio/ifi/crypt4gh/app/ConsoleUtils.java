package no.uio.ifi.crypt4gh.app;

import java.io.Console;

public class ConsoleUtils {

    private static ConsoleUtils ourInstance = new ConsoleUtils();

    public static ConsoleUtils getInstance() {
        return ourInstance;
    }

    private ConsoleUtils() {
    }

    public boolean promptForConfirmation(String prompt) {
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

    public char[] readPassword(String prompt, int minLength) {
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
