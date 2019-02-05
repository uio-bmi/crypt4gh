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

}
