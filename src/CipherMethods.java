import org.mindrot.jbcrypt.BCrypt;
import org.apache.commons.lang3.RandomStringUtils;
import org.passay.*;

import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Base64;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.util.Scanner;

public class CipherMethods {
  public static void main(String[] args) {
    //Testing
//    connectDatabase();
//    addMasterUser("mike", "thisisapass");
//    addMasterUser("jimmy", "thisisalsoapass");
//    addLogin(1, "reddit", "mikeReddit", stringToKey(readKey(getUser(1))));
//    addLogin(1, "facebook", "mikeTwitter", stringToKey(readKey(getUser(1))));
//    addLogin(2, "reddit", "jimmyReddit", stringToKey(readKey(getUser(2))));
//    addLogin(2, "facebook", "jimmyTwitter", stringToKey(readKey(getUser(2))));
//    showLogins(1);
//    System.out.println(login("jimmy", "thisisalsoapasss"));
    
    
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
      return scan.next();
    } catch (FileNotFoundException e) {
      // TODO Auto-generated catch block
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
      // TODO Auto-generated catch block
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
  
  public static String encryptPass(String algorithm, String pass, SecretKey key, String salt) {
    return pass;
  }
  
  public static String decryptPass(String algorithm, String cipherText, SecretKey key, String salt) {
    return cipherText;
  }

  public static void addMasterUser(String user, String pass) {
    String url = "jdbc:sqlite:CipherGuardian.db";
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
    
  }
  
  public static void addLogin(int id, String name, String user, SecretKey key) {
    String pass = generatePass();
    String salt = generateSalt();
    String cipherText = encryptPass("AES", pass, key, salt);
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
    System.out.println("Your generated password is: " + pass + "\nDo not show this password to anyone.");
  }
  
  public static void addLogin(int id, String name, String user, String pass, SecretKey key) {
    String salt = generateSalt();
    String cipherText = encryptPass("AES", pass, key, salt);
    String url = "jdbc:sqlite:CipherGuardian.db";
    try (Connection conn = DriverManager.getConnection(url)) {
      String add = "INSERT INTO login_table (master_id, login_name, login_user, login_pass, login_salt)\n"
          + " VALUES (?, ?, ?, ?);";
      PreparedStatement stmt = conn.prepareStatement(add);
      stmt.setInt(1, id);
      stmt.setString(2, name);
      stmt.setString(3, cipherText);
      stmt.setString(4, salt);
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
      return -11;
    }
  }
  
  public static void editLoginName(int id, String masterUser, String masterPass, String name) {
    String url = "jdbc:sqlite:CipherGuardian.db";
    String getUser = "";
    String getPass = "";
    try (Connection conn = DriverManager.getConnection(url)) {
      int masterID = getMasterID(id);
      if(verifyMaster(masterID, masterUser, masterPass)) {
        String change = "UPDATE login_table SET login_name = ? WHERE login_id = ?;";
        PreparedStatement stmt = conn.prepareStatement(change);
        stmt = conn.prepareStatement(change);
        stmt.setString(1, name);
        stmt.setInt(2, id);
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
  
  public static void editLoginUser(int id, String masterUser, String masterPass, String user) {
    String url = "jdbc:sqlite:CipherGuardian.db";
    String getUser = "";
    String getPass = "";
    try (Connection conn = DriverManager.getConnection(url)) {
      int masterID = getMasterID(id);
      if(verifyMaster(masterID, masterUser, masterPass)) {
        String change = "UPDATE login_table SET login_user = ? WHERE login_id = ?;";
        PreparedStatement stmt = conn.prepareStatement(change);
        stmt = conn.prepareStatement(change);
        stmt.setString(1, user);
        stmt.setInt(2, id);
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
  
  public static void editLoginPass(int id, String masterUser, String masterPass, String pass, SecretKey key) {
    String url = "jdbc:sqlite:CipherGuardian.db";
    String getUser = "";
    String getPass = "";
    try (Connection conn = DriverManager.getConnection(url)) {
      int masterID = getMasterID(id);
      if(verifyMaster(masterID, masterUser, masterPass)) {
        String salt = generateSalt();
        String cipherText = encryptPass("algorithm", pass, key, salt);
        String change = "UPDATE login_table SET login_pass = ? WHERE login_id = ?;";
        PreparedStatement stmt = conn.prepareStatement(change);
        stmt = conn.prepareStatement(change);
        stmt.setString(1, cipherText);
        stmt.setInt(2, id);
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
  }
  
  public static void editLoginPass(int id, String masterUser, String masterPass, SecretKey key) {
    String url = "jdbc:sqlite:CipherGuardian.db";
    String getUser = "";
    String getPass = "";
    try (Connection conn = DriverManager.getConnection(url)) {
      int masterID = getMasterID(id);
      if(verifyMaster(masterID, masterUser, masterPass)) {
        String pass = generatePass();
        String salt = generateSalt();
        String cipherText = encryptPass("algorithm", pass, key, salt);
        String change = "UPDATE login_table SET login_pass = ? WHERE login_id = ?;";
        PreparedStatement stmt = conn.prepareStatement(change);
        stmt = conn.prepareStatement(change);
        stmt.setString(1, cipherText);
        stmt.setInt(2, id);
        stmt.executeUpdate();
        change = "UPDATE login_table SET login_salt = ? WHERE login_id = ?;";
        stmt = conn.prepareStatement(change);
        stmt.setString(1, salt);
        stmt.executeQuery();
        stmt.close();
        conn.close();
        System.out.println("Your generated password is: " + pass + "\nDo not show this password to anyone.");
      } else {
        System.out.println("ERROR: INVALID CREDENTIALS");
      }
    } catch (SQLException e) {
      System.out.println(e.getMessage());
    }
  }
  
  public static void getLogin(int id, SecretKey key) {
    //return a specific login's name and password by decrypting the password using the secret key. Only do so if the master_id of the login_id matches the current user's master_id
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
