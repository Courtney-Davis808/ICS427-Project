package ics427;

import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

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
            System.out.println("Enter your username");
            username = System.console().readLine();
        }
        System.out.print("Enter password: ");
        String password = String.valueOf(System.console().readPassword());

        if (register) {
            System.out.print("Please re enter your password");
            String tmpPassword = String.valueOf(System.console().readPassword());
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
            System.out.println("3: Edit account credentials");
            System.out.println("4: Delete account credentials");
            System.out.println("5: Delete your password manager account");
            System.out.println("6: Exit");
            choice = System.console().readLine().trim();
            loop = choice(choice.trim(), masterId, username, password);
        }

        System.out.println("I am done, so I wipe terminal");
        try {
            if (System.getProperty("os.name").contains("Windows")) {
                new ProcessBuilder("cmd", "/c", "cls").inheritIO().start().waitFor();
            } else {
                Runtime.getRuntime().exec("clear");
            }
        } catch (Exception ignored) {
            System.out.println("Error: " + ignored.getMessage());

        }
        System.out.flush();

    }

    public int addOne(int x) {
        return x + 1;
    }

    public static boolean choice(String choice, int masterId, String username, String password) {
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
            showLogins(masterId);
            System.out.println("Enter the number to get credentials");
            int accountIndex = -1;
            try {
                accountIndex = Integer.parseInt(System.console().readLine());
            } catch (NumberFormatException e) {
                System.out.println("Please enter an integer");
                return true;
            }
            getLogin(masterId, accountIndex);
        } else if (choice.equals("3")) {
            showLogins(masterId);
            System.out.println("Enter the number to edit credentials");
            int accountIndex = -1;
            try {
                accountIndex = Integer.parseInt(System.console().readLine());
            } catch (NumberFormatException e) {
                System.out.println("Please enter an integer");
                return true;
            }
            System.out.println("Please enter the new name, username, or password");
            System.out.println("Enter a blank line if you don't want to change it");
            System.out.println("To generate a password enter \"generate\"");
            System.out.println("Enter new name");
            String newName = System.console().readLine();
            System.out.println("enter new username");
            String newUsername = System.console().readLine();
            System.out.println("Enter new password");
            String newPassword = System.console().readLine();

            if (newName.length() == 0 && newUsername.length() == 0 && newPassword.length() == 0) {
                System.out.println("Not updating anything");
                return true;
            }
            if (newUsername.length() > 0) {
                editLoginUser(masterId, accountIndex, username, password, newUsername);
            }
            if (newName.length() > 0) {
                editLoginName(masterId, accountIndex, username, password, newName);
            }
            if (newPassword.equalsIgnoreCase("generate")) {
                editLoginPass(masterId, accountIndex, username, password);
            } else if (newPassword.length() > 0) {
                editLoginPass(masterId, accountIndex, username, password, newPassword);
            }
        } else if (choice.equals("4")) {
            showLogins(masterId);
            System.out.println("Enter the number of the account you want to delete");
            int accountIndex = -1;
            try {
                accountIndex = Integer.parseInt(System.console().readLine());
            } catch (NumberFormatException e) {
                System.out.println("Please enter an integer");
                return true;
            }
            deleteLogin(masterId, accountIndex, username, password);

        } else if (choice.equals("5")) {
            System.out.println("Are you sure you want to delete your account?");
            System.out.println("Enter y to continue");
            if (System.console().readLine().equalsIgnoreCase("y")) {
                System.out.println("Please re enter your password");
                String tmpPassword = String.valueOf(System.console().readPassword());
                deleteMaster(masterId, username, tmpPassword);
                return false;
            }
        } else {
            return !choice.equals("6");
        }
        return true;
    }


    public static void main(String[] args) {
        int exitCode = new CommandLine(new Main()).execute(args);
        System.exit(exitCode);
    }
}