package ics427;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Base64;
import java.util.Scanner;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.mindrot.jbcrypt.BCrypt;
import org.passay.CharacterData;
import org.passay.CharacterRule;
import org.passay.EnglishCharacterData;
import org.passay.PasswordGenerator;

/**
* Methods to be used with the Cipher Guardian
* program.
*
* @author Michael Chun
* @version 0.9.0
*/
public class CipherMethods {
  public static void main(String[] args) {
    //Testing
    //connectDatabase();
    //addMasterUser("mike", "thisisapass");
    //addMasterUser("mike", "AlsoAPass");
    //addMasterUser("jimmy", "thisisalsoapass");
    //addLogin(1, "reddit", "mikeReddit");
    //addLogin(1, "facebook", "mikeTwitter");
    //addLogin(2, "reddit", "jimmyReddit");
    //addLogin(2, "facebook", "jimmyTwitter");
    //showLogins(1);
    //getLogin(1, 1);
    //showAllLogins();
    //editLoginName(1, 1, "mike", "thisisapass", "NotReddit");
    //editLoginUser(1, 1, "mike", "thisisapass", "NotMike");
    //editLoginPass(1, 1, "mike", "thisisapass", "NewPass");
    //showAllLogins();
    //editLoginPass(1, 1, "mike", "thisisapass");
    //showAllLogins();
    //deleteMaster(1, "mike", "thisisapass");
    //System.out.println("Testing testing testing\n\n");
    //showAllLogins();
    //System.out.println("Testing testing testing\n\n");
    //showAllMasters();
  }
  
  /**
   * Debug Method to show all user's login information
   * in the table regardless of user.
   */
  protected static void showAllLogins() {
    String url = "jdbc:sqlite:CipherGuardian.db";
    try (Connection conn = DriverManager.getConnection(url)) {
      String tableOne = "SELECT * FROM login_table;";
      PreparedStatement stmt = conn.prepareStatement(tableOne);
      stmt = conn.prepareStatement(tableOne);
      ResultSet rs = stmt.executeQuery();
      if (rs.next() == false) {
        System.out.println("ERROR: LOGIN NOT FOUND");
      } else {
        do {
          System.out.print("Login ID: " + rs.getInt("login_id"));
          System.out.print(", Master ID: " + rs.getInt("master_id"));
          System.out.print(", Name: " + rs.getString("login_name"));
          System.out.print(", User: " + rs.getString("login_user"));
          System.out.print(", Pass: " + rs.getString("login_pass"));
          System.out.print(", Salt: " + rs.getString("login_salt"));
          byte[] bytes = rs.getBytes("login_iv");
          System.out.print(", IV: ");
          for (int i = 0; i < 16; i++) {
            System.out.print(bytes[i]);
          }
          System.out.println();
        } while (rs.next());
      }
      rs.close();
      stmt.close();
      conn.close();
      
    } catch (SQLException e) {
      System.out.println(e.getMessage());
    }
  }
  
  /**
   * Debug method used to show all master users information in the table.
   */
  protected static void showAllMasters() {
    String url = "jdbc:sqlite:CipherGuardian.db";
    try (Connection conn = DriverManager.getConnection(url)) {
      String tableOne = "SELECT * FROM master_table;";
      PreparedStatement stmt = conn.prepareStatement(tableOne);
      stmt = conn.prepareStatement(tableOne);
      ResultSet rs = stmt.executeQuery();
      if (rs.next() == false) {
        System.out.println("ERROR: LOGIN NOT FOUND");
      } else {
        do {
          System.out.print("Master ID: " + rs.getInt("master_id"));
          System.out.print(", User: " + rs.getString("master_user"));
          System.out.print(", Pass: " + rs.getString("master_pass"));
          System.out.println();
        } while (rs.next());
      }
      rs.close();
      stmt.close();
      conn.close();
      
    } catch (SQLException e) {
      System.out.println(e.getMessage());
    }
  }
  
  /**
   * Connects to the database. Then checks if tables have been generated.
   * Creates both tables if they don't exist.
   */
  protected static void connectDatabase() {
    String url = "jdbc:sqlite:CipherGuardian.db";

    try (Connection conn = DriverManager.getConnection(url)) {
      String tableOne = "CREATE TABLE IF NOT EXISTS master_table (\n"
          + "master_id integer PRIMARY KEY,\n"
          + "master_user varchar(255) NOT NULL,\n"
          + "master_pass varchar(255) NOT NULL\n"
          + ");";
      String tableTwo = "CREATE TABLE IF NOT EXISTS login_table (\n"
          + "login_id integer PRIMARY KEY,\n"
          + "master_id integer NOT NULL,\n"
          + "login_name varchar(255) NOT NULL,\n"
          + "login_user varchar(255) NOT NULL,\n"
          + "login_pass varchar(255) NOT NULL,\n"
          + "login_salt varchar(255) NOT NULL,\n"
          + "login_iv binary(16) NOT NULL,\n"
          + "FOREIGN KEY(master_id) references table1\n"
          + ");";
      PreparedStatement stmt = conn.prepareStatement(tableOne);
      stmt.executeUpdate();
      stmt = conn.prepareStatement(tableTwo);
      stmt.executeUpdate();
      stmt.close();
      conn.close();

    } catch (SQLException e) {
      System.out.println(e.getMessage());
    }
  }
  
  /**
   * Checks password against BCrypt salt and hashed pass.
   * Returns true if matching, false otherwise.
   *
   * @param input      Input to check
   * @param pass       Salt and Hashed password to be compared to
   */
  private static boolean checkPass(String input, String pass) {
    return BCrypt.checkpw(input, pass);
  }
  
  /**
   * Salts and hashes a password using BCrypt.
   *
   * @param pass       The password to be salt and hashed.
   */
  private static String saltHash(String pass) {
    return BCrypt.hashpw(pass, BCrypt.gensalt());
  }
  
  /**
   * Generates a salt.
   */
  private static String generateSalt() {
    return BCrypt.gensalt();
  }
  
  /**
   * Converts a Secret Key to a string.
   *
   * @param key      Secret Key object to be converted to string
   */
  private static String keyToString(SecretKey key) {
    byte[] data = key.getEncoded();
    String str = Base64.getEncoder().encodeToString(data);
    return str;
  }
  
  /**
   * Converts a string to a Secret Key.
   *
   * @param str      String to be converted to a Secret Key
   */
  private static SecretKey stringToKey(String str) {
    byte[] decoded = Base64.getDecoder().decode(str);
    SecretKey key = new SecretKeySpec(decoded, 0, decoded.length, "AES");
    return key;
  }
  
  /**
   * Checks if a .key file with the username exists and
   * returns the string. To be used with stringToKey.
   *
   * @param user      User's .key file to be checked
   */
  private static String readKey(String user) {
    File file = new File(user + ".key");
    try {
      Scanner scan = new Scanner(file);
      String str = scan.next();
      scan.close();
      return str;
    } catch (FileNotFoundException e) {
      e.printStackTrace();
      return "";
    }
  }
  
  /**
   * Generate a new .key file for the given user.
   *
   * @param user      The user to generate the file for.
   */
  private static void generateKey(String user) {
    try {
      KeyGenerator keyGen = KeyGenerator.getInstance("AES");
      keyGen.init(256);
      SecretKey key = keyGen.generateKey();
      File file = new File(user + ".key");
      if (file.createNewFile()) {
        FileWriter write = new FileWriter(file);
        write.write(keyToString(key));
        write.close();
        System.out.println("Your key has been successfully generated as: " + user + ".key");
        System.out.println("Keep this key safe as you will need it in this program's"
            + " directory when adding or retrieving your login information.");
      }
      
    } catch (NoSuchAlgorithmException e) {
      e.printStackTrace();
    } catch (IOException e) {
      e.printStackTrace();
    }
  }
  
  /**
   * Generates a new 18 digit password for the user.
   * Contains 4 Upper and Lower case letters, 4 digits,
   * and 3 Special characters.
   */
  private static String generatePass() {
    CharacterData lowerChar = EnglishCharacterData.LowerCase;
    CharacterRule lowerRule = new CharacterRule(lowerChar);
    lowerRule.setNumberOfCharacters(4);
    CharacterData upperChar = EnglishCharacterData.UpperCase;
    CharacterRule upperRule = new CharacterRule(upperChar);
    upperRule.setNumberOfCharacters(4);
    CharacterData digitChar = EnglishCharacterData.Digit;
    CharacterRule digitRule = new CharacterRule(digitChar);
    digitRule.setNumberOfCharacters(4);
    CharacterData specialChar = new CharacterData() {
      public String getErrorCode() {
        return "ERROR";
      }
      
      public String getCharacters() {
        return "!@#$%^&*()_+";
      }
    };
    CharacterRule specialRule = new CharacterRule(specialChar);
    specialRule.setNumberOfCharacters(3);
    PasswordGenerator gen = new PasswordGenerator();
    String password = gen.generatePassword(18, specialRule, lowerRule, upperRule, digitRule);
    return password;
    
  }
  
  /**
   * Generate a random 16 byte IV.
   */
  private static byte[] generateIv() {
    byte[] iv = new byte[16];
    new SecureRandom().nextBytes(iv);
    return iv;
  }
  
  /**
   * Encrypt given password using given encryption method
   * Uses provided secret key and adds a salt and IV.
   *
   * @param algorithm   Algorithm to be used in encryption
   * @param pass        Password to be encrypted
   * @param key         Secret Key to be used in encryption   
   * @param salt        Salt to be added to password
   * @param iv          IV to be used in encryption.
   */
  private static String encryptPass(String algorithm, String pass,
      SecretKey key, String salt, byte[] iv) {
    String result = "";
    String saltPass = salt + pass;
    try {
      Cipher cipher = Cipher.getInstance(algorithm);
      cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
      byte[] cipherText = cipher.doFinal(saltPass.getBytes());
      result =  Base64.getEncoder().encodeToString(cipherText);
    } catch (NoSuchPaddingException e) {
      System.out.println("ERROR1");
    } catch (NoSuchAlgorithmException e) {
      System.out.println("ERROR2");
    } catch (InvalidAlgorithmParameterException e) {
      System.out.println("ERROR3");
    } catch (InvalidKeyException e) {
      System.out.println("ERROR4");
    } catch (BadPaddingException e) {
      System.out.println("ERROR5");
    } catch (IllegalBlockSizeException e) {
      System.out.println("ERROR6");
    }
    return result;
  }
  
  /**
   * Decrypt given password using given encryption method
   * Uses provided secret key and removes salt and IV.
   *
   * @param algorithm     Algorithm to be used in Decryption
   * @param cipherText    Password to be Decrypted
   * @param key           Secret Key to be used in Decryption   
   * @param salt          Salt to be added to password
   * @param iv            IV to be used in Decryption.
   */
  private static String decryptPass(String algorithm, String
      cipherText, SecretKey key, String salt, byte[] iv) {
    String result = "";
    int saltSize = salt.length();
    String pass = "";
    try {
      Cipher cipher = Cipher.getInstance(algorithm);
      cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
      byte[] plainText = cipher.doFinal(Base64.getDecoder().decode(cipherText));
      result = new String(plainText);
      pass = result.substring(saltSize);
    } catch (NoSuchPaddingException e) {
      System.out.println("Error 1");
    } catch (NoSuchAlgorithmException e) {
      System.out.println("Error 2");
    } catch (InvalidAlgorithmParameterException e) {
      System.out.println("Error 3");
    } catch (InvalidKeyException e) {
      System.out.println("Error 4");
    } catch (BadPaddingException e) {
      System.out.println("Error 5");
    } catch (IllegalBlockSizeException e) {
      System.out.println("Error 6");
    }
    return pass;
  }
  
  /**
   * Checks if the username exists in the Master table.
   * Returns true if username does not exist.
   *
   * @param user      The user to check for
   */
  private static boolean uniqueUser(String user) {
    String url = "jdbc:sqlite:CipherGuardian.db";
    try (Connection conn = DriverManager.getConnection(url)) {
      String tableOne = "SELECT master_id FROM master_table WHERE master_user = ?;";
      PreparedStatement stmt = conn.prepareStatement(tableOne);
      stmt = conn.prepareStatement(tableOne);
      stmt.setString(1, user);
      ResultSet rs = stmt.executeQuery();
      if (rs.next() == false) {
        rs.close();
        stmt.close();
        conn.close();
        return true;
      } else {
        rs.close();
        stmt.close();
        conn.close();
        return false;
      }
    } catch (SQLException e) {
      System.out.println(e.getMessage());
      return false;
    }
  }
  
  /**
   * Adds the user and password combination to the master table
   * as an account if user doesn't already exist.
   *
   * @param user      Username to use for account
   * @param pass      Password to use for account
   */
  protected static void addMasterUser(String user, String pass) {
    String url = "jdbc:sqlite:CipherGuardian.db";
    if (uniqueUser(user)) {
      try (Connection conn = DriverManager.getConnection(url)) {
        //Check if user already exists
        String add = "INSERT INTO master_table (master_user, master_pass)\n"
            + " VALUES (?, ?);";
        PreparedStatement stmt = conn.prepareStatement(add);
        stmt.setString(1, user);
        stmt.setString(2, saltHash(pass));
        stmt.executeUpdate();
        generateKey(user);
        stmt.close();
        conn.close();
      } catch (SQLException e) {
        System.out.println(e.getMessage());
      }
    } else {
      System.out.println("ERROR: USERNAME ALREADY EXISTS");
    }
    
  }
  
  /**
   * Adds the login to the login table with the provided information.
   * Generates a new password and encrypts it. Gives user generated password.
   *
   * @param id       Master Id of the user to be added
   * @param name     The name of the login (i.e. Twitter, Reddit, etc.)
   * @param user     The username to be used
   */
  protected static void addLogin(int id, String name, String user) {
    String pass = generatePass();
    String salt = generateSalt();
    SecretKey key = stringToKey(readKey(getUser(id)));
    byte[] iv = generateIv();
    String cipherText = encryptPass("AES/CBC/PKCS5PADDING", pass, key, salt, iv);
    String url = "jdbc:sqlite:CipherGuardian.db";
    try (Connection conn = DriverManager.getConnection(url)) {
      String add = "INSERT INTO login_table (master_id, login_name,"
          + "login_user, login_pass, login_salt, login_iv)\n"
          + " VALUES (?, ?, ?, ?, ?, ?);";
      PreparedStatement stmt = conn.prepareStatement(add);
      stmt.setInt(1, id);
      stmt.setString(2, name);
      stmt.setString(3, user);
      stmt.setString(4, cipherText);
      stmt.setString(5, salt);
      stmt.setBytes(6,  iv);
      stmt.executeUpdate();
      stmt.close();
      conn.close();
    } catch (SQLException e) {
      System.out.println(e.getMessage());
    }
    System.out.println("Your generated password is: " + pass
        + "\nDo not show this password to anyone.");
  }
  
  /**
   * Adds the login to the login table with the provided information.
   * Adds provided password encrypted to the database.
   *
   * @param id       Master Id of the user to be added
   * @param name     The name of the login (i.e. Twitter, Reddit, etc.)
   * @param user     The username to be used
   * @param pass     The password to be used
   */
  protected static void addLogin(int id, String name, String user, String pass) {
    String salt = generateSalt();
    byte[] iv = generateIv();
    SecretKey key = stringToKey(readKey(getUser(id)));
    String cipherText = encryptPass("AES/CBC/PKCS5PADDING", pass, key, salt, iv);
    String url = "jdbc:sqlite:CipherGuardian.db";
    try (Connection conn = DriverManager.getConnection(url)) {
      String add = "INSERT INTO login_table (master_id, login_name, login_user,"
          + "login_pass, login_salt, login_iv)\n"
          + " VALUES (?, ?, ?, ?, ?, ?);";
      PreparedStatement stmt = conn.prepareStatement(add);
      stmt.setInt(1, id);
      stmt.setString(2, name);
      stmt.setString(3, user);
      stmt.setString(4, cipherText);
      stmt.setString(5, salt);
      stmt.setBytes(6, iv);
      stmt.executeUpdate();
      stmt.close();
      conn.close();
    } catch (SQLException e) {
      System.out.println(e.getMessage());
    }
  }
  
  /**
   * Retrieves the master Id of the login with the provided login_id.
   *
   * @param id      The login to retrieve the master_id for
   */
  private static int getMasterId(int id) {
    String url = "jdbc:sqlite:CipherGuardian.db";
    int getId = 0;
    try (Connection conn = DriverManager.getConnection(url)) {
      String get = "SELECT master_id FROM login_table WHERE login_id = ?";
      PreparedStatement stmt = conn.prepareStatement(get);
      stmt.setInt(1, id);
      ResultSet rs = stmt.executeQuery();
      if (rs.next() == false) {
        System.out.println("ERROR: LOGIN NOT FOUND");
      } else {
        do {
          getId = rs.getInt("master_id");
        } while (rs.next());
      }
      rs.close();
      stmt.close();
      conn.close();
      return getId;
      
    } catch (SQLException e) {
      System.out.println(e.getMessage());
      return -1;
    }
  }
  
  /**
   * Verify the provided username and password matches
   * the information in the database for the provided master_id.
   * Returns true if user and password matches, false otherwise.
   *
   * @param id              The master_id to get the information from
   * @param masterUser      Master account username
   * @param masterPass      Master account password
   */
  private static boolean verifyMaster(int id, String masterUser, String masterPass) {
    String url = "jdbc:sqlite:CipherGuardian.db";
    String getUser = "";
    String getPass = "";
    try (Connection conn = DriverManager.getConnection(url)) {
      String get = "SELECT master_user, master_pass FROM master_table WHERE master_id = ?";
      PreparedStatement stmt = conn.prepareStatement(get);
      stmt.setInt(1, id);
      ResultSet rs = stmt.executeQuery();
      if (rs.next() == false) {
        System.out.println("ERROR: ACCOUNT NOT FOUND");
        return false;
      } else {
        do {
          getUser = rs.getString("master_user");
          getPass = rs.getString("master_pass");
        } while (rs.next());
        rs.close();
        stmt.close();
        conn.close();
        if (getUser.equals(masterUser)) {
          if (checkPass(masterPass, getPass)) {
            return true;
          } else { 
            System.out.println("ERROR: INVALID CREDENTIALS");
            return false;
          }
        } else {
          System.out.println("ERROR: INVALID CREDENTIALS");
          return false;
        }
      }
      
    } catch (SQLException e) {
      System.out.println(e.getMessage());
      return false;
    }
  }
    
  /**
   * Checks if user exists, and if so, compares provided password
   * to the password of that user. Returns user's master_id if successful.
   * Otherwise returns -1.
   *
   * @param masterUser      Master username
   * @param masterPass      Master password
   */
  protected static int login(String masterUser, String masterPass) {
    String url = "jdbc:sqlite:CipherGuardian.db";
    int getId = -1;
    String getUser = "";
    String getPass = "";
    try (Connection conn = DriverManager.getConnection(url)) {
      String get = "SELECT master_id, master_user, master_pass FROM "
          + "master_table WHERE master_user = ?";
      PreparedStatement stmt = conn.prepareStatement(get);
      stmt.setString(1, masterUser);
      ResultSet rs = stmt.executeQuery();
      if (rs.next() == false) {
        System.out.println("ERROR: INVALID CREDENTIALS");
        return -1;
      } else {
        do {
          getId = rs.getInt("master_id");
          getUser = rs.getString("master_user");
          getPass = rs.getString("master_pass");
        } while (rs.next());
        rs.close();
        stmt.close();
        conn.close();
        if (getUser.equals(masterUser)) {
          if (checkPass(masterPass, getPass)) {
            return getId;
          } else { 
            System.out.println("ERROR: INVALID CREDENTIALS");
            return -1;
          }
        } else {
          System.out.println("ERROR: INVALID CREDENTIALS");
          return -1;
        }
      }
      
    } catch (SQLException e) {
      System.out.println(e.getMessage());
      return -1;
    }
  }
  
  /**
   * Edits the login name of the provided login_id. Verifies that
   * master_id of current user matches the one for the provided login. 
   * Also verifies the username and password of the current master_id
   * before changing.
   *
   * @param masterId     Master id of the current user
   * @param loginId      The login_id of the login to be changed
   * @param masterUser   The master username to be verified
   * @param masterPass   The master password to be verified
   * @param name         The name it will be changed to
   */
  protected static void editLoginName(int masterId, int loginId,
      String masterUser, String masterPass, String name) {
    String url = "jdbc:sqlite:CipherGuardian.db";
    if (masterId == getMasterId(loginId)) {
      try (Connection conn = DriverManager.getConnection(url)) {
        if (verifyMaster(masterId, masterUser, masterPass)) {
          String change = "UPDATE login_table SET login_name = ? WHERE login_id = ?;";
          PreparedStatement stmt = conn.prepareStatement(change);
          stmt = conn.prepareStatement(change);
          stmt.setString(1, name);
          stmt.setInt(2, loginId);
          stmt.executeUpdate();
          stmt.close();
          conn.close();
        } else {
          System.out.println("ERROR: INVALID CREDENTIALS");
        }
      } catch (SQLException e) {
        System.out.println(e.getMessage());
      }
    } else {
      System.out.println("ERROR: CANNOT ACCESS LOGIN");
    }
  }
  
  /**
   * Edits the login username of the provided login_id. Verifies that
   * master_id of current user matches the one for the provided login. 
   * Also verifies the username and password of the current master_id
   * before changing.
   *
   * @param masterId     Master id of the current user
   * @param loginId      The login_id of the login to be changed
   * @param masterUser   The master username to be verified
   * @param masterPass   The master password to be verified
   * @param user         The username it will be changed to
   */
  protected static void editLoginUser(int masterId, int loginId,
      String masterUser, String masterPass, String user) {
    String url = "jdbc:sqlite:CipherGuardian.db";
    if (masterId == getMasterId(loginId)) {
      try (Connection conn = DriverManager.getConnection(url)) {
        if (verifyMaster(masterId, masterUser, masterPass)) {
          String change = "UPDATE login_table SET login_user = ? WHERE login_id = ?;";
          PreparedStatement stmt = conn.prepareStatement(change);
          stmt = conn.prepareStatement(change);
          stmt.setString(1, user);
          stmt.setInt(2, loginId);
          stmt.executeUpdate();
          stmt.close();
          conn.close();
        } else {
          System.out.println("ERROR: INVALID CREDENTIALS");
        }
      } catch (SQLException e) {
        System.out.println(e.getMessage());
      }
    } else {
      System.out.println("ERROR: CANNOT ACCESS LOGIN");
    }
  }
  
  /**
   * Edits the login password of the provided login_id. Verifies that
   * master_id of current user matches the one for the provided login. 
   * Also verifies the username and password of the current master_id
   * before changing.
   *
   * @param masterId     Master id of the current user
   * @param loginId      The login_id of the login to be changed
   * @param masterUser   The master username to be verified
   * @param masterPass   The master password to be verified
   * @param pass         The password it will be changed to
   */
  protected static void editLoginPass(int masterId, int loginId,
      String masterUser, String masterPass, String pass) {
    String url = "jdbc:sqlite:CipherGuardian.db";
    if (masterId == getMasterId(loginId)) {
      try (Connection conn = DriverManager.getConnection(url)) {
        if (verifyMaster(masterId, masterUser, masterPass)) {
          String salt = generateSalt();
          byte[] iv = generateIv();
          SecretKey key = stringToKey(readKey(getUser(masterId)));
          String cipherText = encryptPass("AES/CBC/PKCS5PADDING", pass, key, salt, iv);
          String change = "UPDATE login_table SET login_pass = ? WHERE login_id = ?;";
          PreparedStatement stmt = conn.prepareStatement(change);
          stmt = conn.prepareStatement(change);
          stmt.setString(1, cipherText);
          stmt.setInt(2, loginId);
          stmt.executeUpdate();
          change = "UPDATE login_table SET login_salt = ? WHERE login_id = ?;";
          stmt = conn.prepareStatement(change);
          stmt.setString(1, salt);
          stmt.executeUpdate();
          stmt.close();
          conn.close();
        } else {
          System.out.println("ERROR: INVALID CREDENTIALS");
        }
      } catch (SQLException e) {
        System.out.println(e.getMessage());
      }
    } else {
      System.out.println("ERROR: CANNOT ACCESS LOGIN");
    }
  }
  
  /**
   * Edits the login password of the provided login_id. Verifies that
   * master_id of current user matches the one for the provided login. 
   * Also verifies the username and password of the current master_id
   * before changing. Generates a new password and provides it to the user.
   *
   * @param masterId     Master id of the current user
   * @param loginId      The login_id of the login to be changed
   * @param masterUser   The master username to be verified
   * @param masterPass   The master password to be verified
   */
  protected static void editLoginPass(int masterId, int loginId,
      String masterUser, String masterPass) {
    String url = "jdbc:sqlite:CipherGuardian.db";
    if (masterId == getMasterId(loginId)) {
      try (Connection conn = DriverManager.getConnection(url)) {
        if (verifyMaster(masterId, masterUser, masterPass)) {
          String pass = generatePass();
          String salt = generateSalt();
          byte[] iv = generateIv();
          SecretKey key = stringToKey(readKey(getUser(masterId)));
          String cipherText = encryptPass("AES/CBC/PKCS5PADDING", pass, key, salt, iv);
          String change = "UPDATE login_table SET login_pass = ? WHERE login_id = ?;";
          PreparedStatement stmt = conn.prepareStatement(change);
          stmt = conn.prepareStatement(change);
          stmt.setString(1, cipherText);
          stmt.setInt(2, loginId);
          stmt.executeUpdate();
          change = "UPDATE login_table SET login_salt = ? WHERE login_id = ?;";
          stmt = conn.prepareStatement(change);
          stmt.setString(1, salt);
          stmt.executeUpdate();
          stmt.close();
          conn.close();
          System.out.println("Your generated password is: " + pass
              + "\nDo not show this password to anyone.");
        } else {
          System.out.println("ERROR: INVALID CREDENTIALS");
        }
      } catch (SQLException e) {
        System.out.println(e.getMessage());
      }
    } else {
      System.out.println("ERROR: CANNOT ACCESS LOGIN");
    }
  }
  
  /**
   * Deletes a login. Checks that master_id provided matches the master_id of the login.
   * Verifies the username and password of the provided master_id before deleting.
   *
   * @param masterId     Master id of the current user
   * @param loginId      The login_id of the login to be changed
   * @param masterUser   The master username to be verified
   * @param masterPass   The master password to be verified
   */
  protected static void deleteLogin(int masterId, int loginId,
      String masterUser, String masterPass) {
    String url = "jdbc:sqlite:CipherGuardian.db";
    if (masterId == getMasterId(loginId)) {
      try (Connection conn = DriverManager.getConnection(url)) {
        if (verifyMaster(masterId, masterUser, masterPass)) {
          String change = "DELETE FROM login_table WHERE login_id = ?;";
          PreparedStatement stmt = conn.prepareStatement(change);
          stmt = conn.prepareStatement(change);
          stmt.setInt(1, loginId);
          stmt.executeQuery();
          stmt.close();
          conn.close();
        } else {
          System.out.println("ERROR: INVALID CREDENTIALS");
        }
      } catch (SQLException e) {
        System.out.println(e.getMessage());
      }
    } else {
      System.out.println("ERROR: CANNOT ACCESS LOGIN");
    }
  }
  
  /**
   * Deletes a master account and all logins associated.
   * Verifies the username and password of the provided master_id before deleting.
   *
   * @param masterId     Master id of the current user
   * @param masterUser   The master username to be verified
   * @param masterPass   The master password to be verified
   */
  protected static void deleteMaster(int masterId, String masterUser, String masterPass) {
    String url = "jdbc:sqlite:CipherGuardian.db";
    try (Connection conn = DriverManager.getConnection(url)) {
      if (verifyMaster(masterId, masterUser, masterPass)) {
        String change = "DELETE FROM login_table WHERE master_id = ?;";
        PreparedStatement stmt = conn.prepareStatement(change);
        stmt.setInt(1, masterId);
        stmt.executeUpdate();
        change = "DELETE FROM master_table WHERE master_id = ?;";
        stmt = conn.prepareStatement(change);
        stmt.setInt(1, masterId);
        stmt.executeUpdate();
        stmt.close();
        conn.close();
      } else {
        System.out.println("ERROR: INVALID CREDENTIALS");
      }
    } catch (SQLException e) {
      System.out.println(e.getMessage());
    }
  }
  
  /**
   * Get the login information for a given login_id.
   * Verifies the current master user matches owner of the login.
   *
   * @param masterId     Master id of current user
   * @param loginId      Login to be retrieved
   */
  protected static void getLogin(int masterId, int loginId) {
    String url = "jdbc:sqlite:CipherGuardian.db";
    String name = "";
    String user = "";
    String pass = "";
    String salt = "";
    byte[] iv;
    if (masterId == getMasterId(loginId)) {
      try (Connection conn = DriverManager.getConnection(url)) {
        String get = "SELECT login_name, login_user, login_pass, login_salt,"
            + "login_iv FROM login_table WHERE login_id = ?";
        PreparedStatement stmt = conn.prepareStatement(get);
        stmt.setInt(1, loginId);
        ResultSet rs = stmt.executeQuery();
        if (rs.next() == false) {
          System.out.println("ERROR: LOGIN NOT FOUND");
        } else {
          do {
            name = rs.getString("login_name");
            salt = rs.getString("login_salt");
            user = rs.getString("login_user");
            iv = rs.getBytes("login_iv");
            SecretKey key = stringToKey(readKey(getUser(masterId)));
            pass = decryptPass("AES/CBC/PKCS5PADDING", rs.getString("login_pass"), key, salt, iv);
            System.out.println(name);
            System.out.println("Login: " + user);
            System.out.println("Pass: " + pass);
          } while (rs.next());
          rs.close();
          stmt.close();
          conn.close();
        }
        
      } catch (SQLException e) {
        System.out.println(e.getMessage());
      }
    } else {
      System.out.println("ERROR: CANNOT ACCESS LOGIN");
    }
  }
  
  /**
   * Show all logins for the current user.
   * Only lists login names (Reddit, Twitter, etc.)
   *
   * @param id      Master_id of the user to retrieve logins for
   */
  protected static void showLogins(int id) {
    String url = "jdbc:sqlite:CipherGuardian.db";
    String getId = "";
    String getName = "";
    try (Connection conn = DriverManager.getConnection(url)) {
      String get = "SELECT login_id, login_name FROM login_table WHERE master_id = ?";
      PreparedStatement stmt = conn.prepareStatement(get);
      stmt.setInt(1, id);
      ResultSet rs = stmt.executeQuery();
      if (rs.next() == false) {
        System.out.println("ERROR: ACCOUNT NOT FOUND");
      } else {
        do {
          getId = rs.getString("login_id");
          getName = rs.getString("login_name");
          System.out.println(getId + ": " + getName);
        } while (rs.next());
        rs.close();
        stmt.close();
        conn.close();
      }
    } catch (SQLException e) {
      System.out.println(e.getMessage());
    }
  }
  
  /**
   * Get the username of a given master_id.
   *
   * @param id      Master_id of the user to retrieve username for
   */
  private static String getUser(int id) {
    String url = "jdbc:sqlite:CipherGuardian.db";
    String getUser = "";
    try (Connection conn = DriverManager.getConnection(url)) {
      String get = "SELECT master_user FROM master_table WHERE master_id = ?";
      PreparedStatement stmt = conn.prepareStatement(get);
      stmt.setInt(1, id);
      ResultSet rs = stmt.executeQuery();
      if (rs.next() == false) {
        System.out.println("ERROR: ACCOUNT NOT FOUND");
        return "";
      } else {
        do {
          getUser = rs.getString("master_user");
        } while (rs.next());
        rs.close();
        stmt.close();
        conn.close();
        return getUser;
      }
    } catch (SQLException e) {
      System.out.println(e.getMessage());
      return "";
    }
  }
}
