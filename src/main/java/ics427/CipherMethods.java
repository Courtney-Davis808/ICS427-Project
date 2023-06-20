package ics427;

import org.mindrot.jbcrypt.BCrypt;
import org.passay.*;

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

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.util.Scanner;

public class CipherMethods {
  public static void main(String[] args) {
    //Testing
    connectDatabase();
//    addMasterUser("mike", "thisisapass");
//    addMasterUser("mike", "AlsoAPass");
//    addMasterUser("jimmy", "thisisalsoapass");
//    addLogin(1, "reddit", "mikeReddit");
//    addLogin(1, "facebook", "mikeTwitter");
//    addLogin(2, "reddit", "jimmyReddit");
//    addLogin(2, "facebook", "jimmyTwitter");
//    showLogins(1);
//    getLogin(1,1);
//    showAllLogins();
//    editLoginName(1, 1, "mike", "thisisapass", "NotReddit");
//    editLoginUser(1, 1, "mike", "thisisapass", "NotMike");
//    editLoginPass(1, 1, "mike", "thisisapass", "NewPass");
//    showAllLogins();
//    editLoginPass(1, 1, "mike", "thisisapass");
//    showAllLogins();
    
  }
  
  public static void showAllLogins() {
    String url = "jdbc:sqlite:CipherGuardian.db";
    try (Connection conn = DriverManager.getConnection(url)) {
      String tableOne = "SELECT * FROM login_table;";
      PreparedStatement stmt = conn.prepareStatement(tableOne);
      stmt = conn.prepareStatement(tableOne);
      ResultSet rs = stmt.executeQuery();
      if(rs.next() == false) {
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
          for(int i = 0; i < 16; i++) {
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
  
  public static void showAllMasters() {
    String url = "jdbc:sqlite:CipherGuardian.db";
    try (Connection conn = DriverManager.getConnection(url)) {
      String tableOne = "SELECT * FROM master_table;";
      PreparedStatement stmt = conn.prepareStatement(tableOne);
      stmt = conn.prepareStatement(tableOne);
      ResultSet rs = stmt.executeQuery();
      if(rs.next() == false) {
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
  
  /* Creates new database if doesn't exist
     Generates tables if they don't exist */
  public static void connectDatabase() {
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
  
  public static boolean checkPass(String input, String pass) {
    return BCrypt.checkpw(input, pass);
  }

  public static String saltHash(String pass) {
    return BCrypt.hashpw(pass, BCrypt.gensalt());
  }
  
  public static String generateSalt() {
    return BCrypt.gensalt();
  }
  
  public static String keyToString(SecretKey key) {
    byte[] data = key.getEncoded();
    String str = Base64.getEncoder().encodeToString(data);
    return str;
  }
  
  public static SecretKey stringToKey(String str) {
    byte[] decoded = Base64.getDecoder().decode(str);
    SecretKey key = new SecretKeySpec(decoded, 0, decoded.length, "AES");
    return key;
  }
  
  public static String readKey(String user) {
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
  
  public static void generateKey(String user) {
    try {
      KeyGenerator keyGen = KeyGenerator.getInstance("AES");
      keyGen.init(256);
      SecretKey key = keyGen.generateKey();
      File file = new File(user + ".key");
      if(file.createNewFile()) {
        FileWriter write = new FileWriter(file);
        write.write(keyToString(key));
        write.close();
        System.out.println("Your key has been successfully generated as: " + user + ".key");
        System.out.println("Keep this key safe as you will need it in this program's directory when adding or retrieving your login information.");
      }
      
    } catch (NoSuchAlgorithmException e) {
      e.printStackTrace();
    } catch (IOException e) {
      e.printStackTrace();
    }
  }
  
  public static String generatePass() {
    PasswordGenerator gen = new PasswordGenerator();
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
    
    String password = gen.generatePassword(18, specialRule ,lowerRule, upperRule, digitRule);
    return password;
    
  }
  
  public static byte[] generateIV() {
    byte[] iv = new byte[16];
    new SecureRandom().nextBytes(iv);
    return iv;
  }
  
  public static String encryptPass(String algorithm, String pass, SecretKey key, String salt, byte[] iv) {
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
  
  public static String decryptPass(String algorithm, String cipherText, SecretKey key, String salt, byte[] iv) {
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
      
    } catch (NoSuchAlgorithmException e) {
      
    } catch (InvalidAlgorithmParameterException e) {
      
    } catch (InvalidKeyException e) {
      
    } catch (BadPaddingException e) {
      
    } catch (IllegalBlockSizeException e) {
      
    }
    return pass;
  }
  
  public static boolean uniqueUser(String user) {
    String url = "jdbc:sqlite:CipherGuardian.db";
    try (Connection conn = DriverManager.getConnection(url)) {
      String tableOne = "SELECT master_id FROM master_table WHERE master_user = ?;";
      PreparedStatement stmt = conn.prepareStatement(tableOne);
      stmt = conn.prepareStatement(tableOne);
      ResultSet rs = stmt.executeQuery();
      if(rs.next() == false) {
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

  public static void addMasterUser(String user, String pass) {
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
  
  public static void addLogin(int id, String name, String user) {
    String pass = generatePass();
    String salt = generateSalt();
    SecretKey key = stringToKey(readKey(getUser(id)));
    byte[] iv = generateIV();
    String cipherText = encryptPass("AES/CBC/PKCS5PADDING", pass, key, salt, iv);
    String url = "jdbc:sqlite:CipherGuardian.db";
    try (Connection conn = DriverManager.getConnection(url)) {
      String add = "INSERT INTO login_table (master_id, login_name, login_user, login_pass, login_salt, login_iv)\n"
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
    System.out.println("Your generated password is: " + pass + "\nDo not show this password to anyone.");
  }
  
  public static void addLogin(int id, String name, String user, String pass) {
    String salt = generateSalt();
    byte[] iv = generateIV();
    SecretKey key = stringToKey(readKey(getUser(id)));
    String cipherText = encryptPass("AES/CBC/PKCS5PADDING", pass, key, salt, iv);
    String url = "jdbc:sqlite:CipherGuardian.db";
    try (Connection conn = DriverManager.getConnection(url)) {
      String add = "INSERT INTO login_table (master_id, login_name, login_user, login_pass, login_salt)\n"
          + " VALUES (?, ?, ?, ?, ?);";
      PreparedStatement stmt = conn.prepareStatement(add);
      stmt.setInt(1, id);
      stmt.setString(2, name);
      stmt.setString(3, user);
      stmt.setString(4, cipherText);
      stmt.setString(5, salt);
      stmt.executeUpdate();
      stmt.close();
      conn.close();
    } catch (SQLException e) {
      System.out.println(e.getMessage());
    }
  }
  
  public static int getMasterID(int id) {
    String url = "jdbc:sqlite:CipherGuardian.db";
    int getID = 0;
    try (Connection conn = DriverManager.getConnection(url)) {
      String get = "SELECT master_id FROM login_table WHERE login_id = ?";
      PreparedStatement stmt = conn.prepareStatement(get);
      stmt.setInt(1, id);
      ResultSet rs = stmt.executeQuery();
      if(rs.next() == false) {
        System.out.println("ERROR: LOGIN NOT FOUND");
      } else {
        do {
          getID = rs.getInt("master_id");
        } while (rs.next());
      }
      rs.close();
      stmt.close();
      conn.close();
      return getID;
      
    } catch (SQLException e) {
      System.out.println(e.getMessage());
      return -1;
    }
  }
  
  public static boolean verifyMaster(int id, String masterUser, String masterPass) {
    String url = "jdbc:sqlite:CipherGuardian.db";
    String getUser = "";
    String getPass = "";
    try (Connection conn = DriverManager.getConnection(url)) {
      String get = "SELECT master_user, master_pass FROM master_table WHERE master_id = ?";
      PreparedStatement stmt = conn.prepareStatement(get);
      stmt.setInt(1, id);
      ResultSet rs = stmt.executeQuery();
      if(rs.next() == false) {
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
        if(getUser.equals(masterUser)) {
          if(checkPass(masterPass, getPass)) {
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
    
  public static int login(String masterUser, String masterPass) {
    String url = "jdbc:sqlite:CipherGuardian.db";
    int getID = -1;
    String getUser = "";
    String getPass = "";
    try (Connection conn = DriverManager.getConnection(url)) {
      String get = "SELECT master_id, master_user, master_pass FROM master_table WHERE master_user = ?";
      PreparedStatement stmt = conn.prepareStatement(get);
      stmt.setString(1, masterUser);
      ResultSet rs = stmt.executeQuery();
      if(rs.next() == false) {
        System.out.println("ERROR: ACCOUNT NOT FOUND");
        return -1;
      } else {
        do {
          getID = rs.getInt("master_id");
          getUser = rs.getString("master_user");
          getPass = rs.getString("master_pass");
        } while (rs.next());
        rs.close();
        stmt.close();
        conn.close();
        if(getUser.equals(masterUser)) {
          if(checkPass(masterPass, getPass)) {
            return getID;
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
  
  public static void editLoginName(int master_id, int login_id, String masterUser, String masterPass, String name) {
    String url = "jdbc:sqlite:CipherGuardian.db";
    if (master_id == getMasterID(login_id)) {
      try (Connection conn = DriverManager.getConnection(url)) {
        int masterID = getMasterID(login_id);
        if(verifyMaster(masterID, masterUser, masterPass)) {
          String change = "UPDATE login_table SET login_name = ? WHERE login_id = ?;";
          PreparedStatement stmt = conn.prepareStatement(change);
          stmt = conn.prepareStatement(change);
          stmt.setString(1, name);
          stmt.setInt(2, login_id);
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
  
  public static void editLoginUser(int master_id, int login_id, String masterUser, String masterPass, String user) {
    String url = "jdbc:sqlite:CipherGuardian.db";
    if(master_id == getMasterID(login_id)) {
      try (Connection conn = DriverManager.getConnection(url)) {
        int masterID = getMasterID(login_id);
        if(verifyMaster(masterID, masterUser, masterPass)) {
          String change = "UPDATE login_table SET login_user = ? WHERE login_id = ?;";
          PreparedStatement stmt = conn.prepareStatement(change);
          stmt = conn.prepareStatement(change);
          stmt.setString(1, user);
          stmt.setInt(2, login_id);
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
  
  public static void editLoginPass(int master_id, int login_id, String masterUser, String masterPass, String pass) {
    String url = "jdbc:sqlite:CipherGuardian.db";
    if (master_id == getMasterID(login_id)) {
      try (Connection conn = DriverManager.getConnection(url)) {
        int masterID = getMasterID(login_id);
        if(verifyMaster(masterID, masterUser, masterPass)) {
          String salt = generateSalt();
          byte[] iv = generateIV();
          SecretKey key = stringToKey(readKey(getUser(master_id)));
          String cipherText = encryptPass("AES/CBC/PKCS5PADDING", pass, key, salt, iv);
          String change = "UPDATE login_table SET login_pass = ? WHERE login_id = ?;";
          PreparedStatement stmt = conn.prepareStatement(change);
          stmt = conn.prepareStatement(change);
          stmt.setString(1, cipherText);
          stmt.setInt(2, login_id);
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
  
  public static void editLoginPass(int master_id, int login_id, String masterUser, String masterPass) {
    String url = "jdbc:sqlite:CipherGuardian.db";
    if (master_id == getMasterID(login_id)) {
      try (Connection conn = DriverManager.getConnection(url)) {
        int masterID = getMasterID(login_id);
        if(verifyMaster(masterID, masterUser, masterPass)) {
          String pass = generatePass();
          String salt = generateSalt();
          byte[] iv = generateIV();
          SecretKey key = stringToKey(readKey(getUser(master_id)));
          String cipherText = encryptPass("AES/CBC/PKCS5PADDING", pass, key, salt, iv);
          String change = "UPDATE login_table SET login_pass = ? WHERE login_id = ?;";
          PreparedStatement stmt = conn.prepareStatement(change);
          stmt = conn.prepareStatement(change);
          stmt.setString(1, cipherText);
          stmt.setInt(2, login_id);
          stmt.executeUpdate();
          change = "UPDATE login_table SET login_salt = ? WHERE login_id = ?;";
          stmt = conn.prepareStatement(change);
          stmt.setString(1, salt);
          stmt.executeUpdate();
          stmt.close();
          conn.close();
          System.out.println("Your generated password is: " + pass + "\nDo not show this password to anyone.");
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
  
  public static void deleteLogin(int master_id, int login_id, String masterUser, String masterPass) {
    String url = "jdbc:sqlite:CipherGuardian.db";
    if (master_id == getMasterID(login_id)) {
      try (Connection conn = DriverManager.getConnection(url)) {
        int masterID = getMasterID(login_id);
        if(verifyMaster(masterID, masterUser, masterPass)) {
          String change = "DELETE FROM login_table WHERE login_id = ?;";
          PreparedStatement stmt = conn.prepareStatement(change);
          stmt = conn.prepareStatement(change);
          stmt.setInt(1, login_id);
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
  
  public static void deleteMaster(int master_id, String masterUser, String masterPass) {
    String url = "jdbc:sqlite:CipherGuardian.db";
    try (Connection conn = DriverManager.getConnection(url)) {
      if(verifyMaster(master_id, masterUser, masterPass)) {
        String change = "DELETE FROM master_table WHERE master_id = ?;";
        PreparedStatement stmt = conn.prepareStatement(change);
        stmt = conn.prepareStatement(change);
        stmt.setInt(1, master_id);
        stmt.executeQuery();
        stmt.close();
        conn.close();
      } else {
        System.out.println("ERROR: INVALID CREDENTIALS");
      }
    } catch (SQLException e) {
      System.out.println(e.getMessage());
    }
  }
  
  public static void getLogin(int master_id, int login_id) {
    //return a specific login's name and password by decrypting the password using the secret key. Only do so if the master_id of the login_id matches the current user's master_id
    String url = "jdbc:sqlite:CipherGuardian.db";
    String name = "";
    String user = "";
    String pass = "";
    String salt = "";
    byte[] iv;
    if (master_id == getMasterID(login_id)) {
      try (Connection conn = DriverManager.getConnection(url)) {
        String get = "SELECT login_name, login_user, login_pass, login_salt, login_iv FROM login_table WHERE login_id = ?";
        PreparedStatement stmt = conn.prepareStatement(get);
        stmt.setInt(1, login_id);
        ResultSet rs = stmt.executeQuery();
        if(rs.next() == false) {
          System.out.println("ERROR: LOGIN NOT FOUND");
        } else {
          do {
            name = rs.getString("login_name");
            salt = rs.getString("login_salt");
            user = rs.getString("login_user");
            iv = rs.getBytes("login_iv");
            SecretKey key = stringToKey(readKey(getUser(master_id)));
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
  
  public static void showLogins(int id) {
    String url = "jdbc:sqlite:CipherGuardian.db";
    String getID = "";
    String getName = "";
    try (Connection conn = DriverManager.getConnection(url)) {
      String get = "SELECT login_id, login_name FROM login_table WHERE master_id = ?";
      PreparedStatement stmt = conn.prepareStatement(get);
      stmt.setInt(1, id);
      ResultSet rs = stmt.executeQuery();
      if(rs.next() == false) {
        System.out.println("ERROR: ACCOUNT NOT FOUND");
      } else {
        do {
          getID = rs.getString("login_id");
          getName = rs.getString("login_name");
          System.out.println(getID + ": " + getName);
        } while (rs.next());
        rs.close();
        stmt.close();
        conn.close();
      }
    } catch (SQLException e) {
      System.out.println(e.getMessage());
    }
  }
  
  public static String getUser(int id) {
    String url = "jdbc:sqlite:CipherGuardian.db";
    String getUser = "";
    try (Connection conn = DriverManager.getConnection(url)) {
      String get = "SELECT master_user FROM master_table WHERE master_id = ?";
      PreparedStatement stmt = conn.prepareStatement(get);
      stmt.setInt(1, id);
      ResultSet rs = stmt.executeQuery();
      if(rs.next() == false) {
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
