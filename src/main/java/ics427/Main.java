package ics427;

import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;
import picocli.CommandLine.HelpCommand;

import java.io.Console;
import java.io.File;
import java.io.Console.*;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.sql.SQLOutput;
import java.util.Arrays;
import java.util.concurrent.Callable;

@Command(name = "cg",
        subcommands = { CommandLine.HelpCommand.class },
        description = "Password manager")
public class Main {
    @Command(name = "login", description = "Login")
    void loginMethod (
            @Option(names = {"-u", "--user" }, description = "Username") String username,
            @Option(names = {"-c", "--create" }, description = "Register account") boolean register
    ) {
        boolean loop = true;
        String choice = "";
        if (username == null) {
            username = System.console().readLine();
            System.out.println("Username: " + username);
        }
        System.out.print("Enter password: ");
        char[] password = System.console().readPassword();

        if (register) {
            System.out.print("Please re enter your password");
            char[] tmpPassword = System.console().readPassword();
            if (!Arrays.equals(password, tmpPassword)) {
                System.out.println("Passwords don't match");
                return;
            }
            System.out.println("Register account with database");
        } else {
            System.out.println("Login to database");
        }
        while (loop) {
            System.out.println("Please select a choice");
            System.out.println("1: Add account");
            System.out.println("2: Get credentials from list of accounts");
            choice = System.console().readLine();
            loop = !(choice.equals("1") || choice.equals("2") || choice.equals("3"));
        }
        if (choice.equals("1")) {
            System.out.println("Another while loop asking to generate password and stuff");
        } else if (choice.equals("2")) {
            System.out.println("Another loop displaying the list of all accounts and when they select the account it prints out their credentials");
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

    public static void main(String[] args) {
        int exitCode = new CommandLine(new Main()).execute(args);
        System.exit(exitCode);
    }
}