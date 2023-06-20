package ics427;

import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import java.util.Arrays;

import static ics427.CipherMethods.*;


@Command(name = "cg",
        subcommands = { CommandLine.HelpCommand.class },
        description = "Password manager")
public class Main {
    @Command(name = "login", description = "Login")
    void loginMethod (
            @Option(names = {"-u", "--user" }, description = "Username") String username,
            @Option(names = {"-c", "--create" }, description = "Register account") boolean register
    ) {
        connectDatabase();
        boolean loop = true;
        String choice = "";
        if (username == null) {
            username = System.console().readLine();
            System.out.println("Username: " + username);
        }
        System.out.print("Enter password: ");
        String password = Arrays.toString(System.console().readPassword());

        if (register) {
            System.out.print("Please re enter your password");
            String tmpPassword = Arrays.toString(System.console().readPassword());
            if (!password.equals(tmpPassword)) {
                System.out.println("Passwords don't match");
                return;
            }
            System.out.println("Register account with database...");
            addMasterUser(username, password);
        }
        int masterId = login(username, password);
        if (masterId == -1) return;
        System.out.println("Logging in...");
        while (loop) {
            System.out.println("Please select a choice");
            System.out.println("1: Add account");
            System.out.println("2: Get credentials from list of accounts");
            choice = System.console().readLine().trim();
            loop = !(choice.equals("1") || choice.equals("2") || choice.equals("3"));
        }
        if (choice.equals("1")) {
            System.out.println("Please enter what account the credentials are for");
            String accountName = System.console().readLine().trim();
            System.out.println("Please enter your username");
            String accountUsername = System.console().readLine().trim();
            System.out.println("Please enter your password or leave it blank if you would like to generate a secure password");
            char[] accountPassword = System.console().readPassword();
            if (accountPassword.length > 0) {
                addLogin(masterId, accountName, accountUsername, String.valueOf(accountPassword));
            } else {
                addLogin(masterId, accountName, accountUsername);
            }
            System.out.println("Account added");

        } else if (choice.equals("2")) {
            System.out.println("Another loop displaying the list of all accounts and when they select the account it prints out their credentials");
            showLogins(masterId);
            System.out.println("Enter the number to get credentials");
            int accountIndex = -1;
            try {
                accountIndex = Integer.parseInt(System.console().readLine());
            } catch (NumberFormatException e) {
                System.out.println("Please enter an integer");
                return;
            }
            getLogin(masterId, accountIndex);
        }

        System.out.println("I am done, so I wipe terminal");
        try {
            if (System.getProperty("os.name").contains("Windows")) {
                new ProcessBuilder("cmd", "/c", "cls").inheritIO().start().waitFor();
            } else {
                Runtime.getRuntime().exec("clear");
            }
        } catch (Exception ignored) {
            System.out.println("FJKDLSFJS");

        }
        System.out.flush();

    }

    public int addOne(int x) {
        return x + 1;
    }

    public static void main(String[] args) {
        int exitCode = new CommandLine(new Main()).execute(args);
        System.exit(exitCode);
    }
}