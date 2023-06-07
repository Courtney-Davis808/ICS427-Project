package ics427;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

import java.io.Console;
import java.io.File;
import java.io.Console.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.sql.SQLOutput;
import java.util.Arrays;
import java.util.concurrent.Callable;

@Command(name = "login", mixinStandardHelpOptions = true, version = "checksum 4.0",
        description = "Aks for user credentials")
class Login implements Runnable {
    @Option(names = {"-u", "--user"}, description = "User name")
    String user;

    @Option(names = {"-p", "--password"}, description = "Passphrase", interactive = true)
    char[] password;

    public void run() {
        Console cons = System.console();
        System.out.println(password);
        System.out.println(user);
        user = new String(cons.readPassword());
        System.out.println("Username: " + user);
        password = cons.readPassword();
        System.out.println("Password: " + Arrays.toString(password));

    }

    private String base64(byte[] arr) { return new String(arr, StandardCharsets.UTF_8); }

    public static void main(String... args) {
        int exitCode = new CommandLine(new Login()).execute(args);
        System.exit(exitCode);
    }
}