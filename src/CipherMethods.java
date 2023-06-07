import org.mindrot.jbcrypt.BCrypt;

import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CipherMethods {
  public static void main(String[] args) {

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
      Statement stmt = conn.createStatement();
      stmt.execute(tableOne);
      stmt.execute(tableTwo);

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
    return "123abc";
  }
  
  public static void generateKey() {
    System.out.println("Generate a key and store it on the user's computer.");
  }
  
  public static String generatePass() {
    return "123abc";
  }
  
  public static String encryptPass(String algorithm, String pass, String key, String salt) {
    return "123abc";
  }
  
  public static String decryptPass(String algorithm, String cipherText, String key, String salt) {
    return "123abc";
  }
  
  public static String sanitize(String input) {
    return "123abc";
  }

  public static void addMasterUser(String user, String pass) {
    String sanitizeUser = sanitize(user);
    String sanitizePass = sanitize(pass);
    String url = "jdbc:sqlite:CipherGuardian.db";
    try (Connection conn = DriverManager.getConnection(url)) {
      Statement stmt = conn.createStatement();
      String add = "INSERT INTO master_table (master_user, master_pass)\n"
          + " VALUES ('" + sanitizeUser + "', '" + saltHash(sanitizePass) + "');";
      stmt.execute(add);
    } catch (SQLException e) {
      System.out.println(e.getMessage());
    }
  }
  
  public static void addLogin(int id, String name, String user, String key) {
    String sanitizeName = sanitize(name);
    String sanitizeUser = sanitize(user);
    String sanitizeKey = sanitize(key);
    String pass = generatePass();
    String salt = generateSalt();
    String cipherText = encryptPass("algorithm", pass, sanitizeKey, salt);
    String url = "jdbc:sqlite:CipherGuardian.db";
    try (Connection conn = DriverManager.getConnection(url)) {
      Statement stmt = conn.createStatement();
      String add = "INSERT INTO login_table (master_id, login_name, login_user, login_pass, login_salt)\n"
          + " VALUES ('" + id + "', '" + sanitizeName + "', '" + cipherText + "', '" + salt + "');";
      stmt.execute(add);
    } catch (SQLException e) {
      System.out.println(e.getMessage());
    }
    System.out.println("Your generated password is: " + pass + "\nDo not show this password to anyone.");
  }
  
  public static void addLogin(int id, String name, String user, String pass, String key) {
    String sanitizeName = sanitize(name);
    String sanitizeUser = sanitize(user);
    String sanitizePass = sanitize(pass);
    String sanitizeKey = sanitize(key);
    String salt = generateSalt();
    String cipherText = encryptPass("algorithm", sanitizePass, sanitizeKey, salt);
    String url = "jdbc:sqlite:CipherGuardian.db";
    try (Connection conn = DriverManager.getConnection(url)) {
      Statement stmt = conn.createStatement();
      String add = "INSERT INTO login_table (master_id, login_name, login_user, login_pass, login_salt)\n"
          + " VALUES ('" + id + "', '" + sanitizeName + "', '" + cipherText + "', '" + salt + "');";
      stmt.execute(add);
    } catch (SQLException e) {
      System.out.println(e.getMessage());
    }
  }
  
  public static void editLoginName(int id, String masterUser, String masterPass, String name) {
    String sanitizeMasterUser = sanitize(masterUser);
    String sanitizeMasterPass = sanitize(masterPass);
    String sanitizeName = sanitize(name);
    String url = "jdbc:sqlite:CipherGuardian.db";
    String getUser = "";
    String getPass = "";
    try (Connection conn = DriverManager.getConnection(url)) {
      Statement stmt = conn.createStatement();
      String get = "SELECT master_user, master_pass FROM master_table WHERE ";
      //Fix, should select the master_user and master_pass from the master_table where the login_table.master_user matches masterUser and login_table.login_id matches id
      ResultSet rs = stmt.executeQuery(get);
      if(rs.next() == false) {
        System.out.println("ERROR: ACCOUNT NOT FOUND");
      } else {
        do {
          getUser = rs.getString("master_user");
          getPass = rs.getString("master_pass");
        } while (rs.next());
      }
      if(getUser.equals(sanitizeMasterUser)) {
        if(checkPass(sanitizeMasterPass, getPass)) {
          String change = "UPDATE login_table SET login_name = '" + sanitizeName + "' WHERE login_id = '" + id + "';";
          stmt.execute(change);
        } else {
          System.out.println("ERROR: INVALID CREDENTIALS");
        }
      } else {
        System.out.println("ERROR: INVALID CREDENTIALS");
      }
    } catch (SQLException e) {
      System.out.println(e.getMessage());
    }
  }
  
  public static void editLoginUser(int id, String masterUser, String masterPass, String user) {
    String sanitizeMasterUser = sanitize(masterUser);
    String sanitizeMasterPass = sanitize(masterPass);
    String sanitizeUser = sanitize(user);
    String url = "jdbc:sqlite:CipherGuardian.db";
    String getUser = "";
    String getPass = "";
    try (Connection conn = DriverManager.getConnection(url)) {
      Statement stmt = conn.createStatement();
      String get = "SELECT master_user, master_pass FROM master_table WHERE ";
      //Fix, should select the master_user and master_pass from the master_table where the login_table.master_user matches masterUser and login_table.login_id matches id
      ResultSet rs = stmt.executeQuery(get);
      if(rs.next() == false) {
        System.out.println("ERROR: ACCOUNT NOT FOUND");
      } else {
        do {
          getUser = rs.getString("master_user");
          getPass = rs.getString("master_pass");
        } while (rs.next());
      }
      if(getUser.equals(sanitizeMasterUser)) {
        if(checkPass(sanitizeMasterPass, getPass)) {
          String change = "UPDATE login_table SET login_user = '" + sanitizeUser + "' WHERE login_id = '" + id + "';";
          stmt.execute(change);
        } else {
          System.out.println("ERROR: INVALID CREDENTIALS");
        }
      } else {
        System.out.println("ERROR: INVALID CREDENTIALS");
      }
    } catch (SQLException e) {
      System.out.println(e.getMessage());
    }
  }
  
  public static void editLoginPass(int id, String masterUser, String masterPass, String pass, String key) {
    String sanitizeMasterUser = sanitize(masterUser);
    String sanitizeMasterPass = sanitize(masterPass);
    String sanitizePass = sanitize(pass);
    String sanitizeKey = sanitize(key);
    String url = "jdbc:sqlite:CipherGuardian.db";
    String getUser = "";
    String getPass = "";
    try (Connection conn = DriverManager.getConnection(url)) {
      Statement stmt = conn.createStatement();
      String get = "SELECT master_user, master_pass FROM master_table WHERE ";
      //Fix, should select the master_user and master_pass from the master_table where the login_table.master_user matches masterUser and login_table.login_id matches id
      ResultSet rs = stmt.executeQuery(get);
      if(rs.next() == false) {
        System.out.println("ERROR: ACCOUNT NOT FOUND");
      } else {
        do {
          getUser = rs.getString("master_user");
          getPass = rs.getString("master_pass");
        } while (rs.next());
      }
      if(getUser.equals(sanitizeMasterUser)) {
        if(checkPass(sanitizeMasterPass, getPass)) {
          String salt = generateSalt();
          String cipherText = encryptPass("algorithm", sanitizePass, sanitizeKey, salt);
          String change = "UPDATE login_table SET login_pass = '" + cipherText + "' WHERE login_id = '" + id + "';";
          stmt.execute(change);
          change = "UPDATE login_table SET login_salt = '" + salt + "' WHERE login_id = '" + id + "';";
        } else {
          System.out.println("ERROR: INVALID CREDENTIALS");
        }
      } else {
        System.out.println("ERROR: INVALID CREDENTIALS");
      }
    } catch (SQLException e) {
      System.out.println(e.getMessage());
    }
  }
  
  public static void editLoginPass(int id, String masterUser, String masterPass, String key) {
    String sanitizeMasterUser = sanitize(masterUser);
    String sanitizeMasterPass = sanitize(masterPass);
    String sanitizeKey = sanitize(key);
    String url = "jdbc:sqlite:CipherGuardian.db";
    String getUser = "";
    String getPass = "";
    String pass = "";
    try (Connection conn = DriverManager.getConnection(url)) {
      Statement stmt = conn.createStatement();
      String get = "SELECT master_user, master_pass FROM master_table WHERE ";
      //Fix, should select the master_user and master_pass from the master_table where the login_table.master_user matches masterUser and login_table.login_id matches id
      ResultSet rs = stmt.executeQuery(get);
      if(rs.next() == false) {
        System.out.println("ERROR: ACCOUNT NOT FOUND");
      } else {
        do {
          getUser = rs.getString("master_user");
          getPass = rs.getString("master_pass");
        } while (rs.next());
      }
      if(getUser.equals(sanitizeMasterUser)) {
        if(checkPass(sanitizeMasterPass, getPass)) {
          pass = generatePass();
          String salt = generateSalt();
          String cipherText = encryptPass("algorithm", pass, sanitizeKey, salt);
          String change = "UPDATE login_table SET login_pass = '" + cipherText + "' WHERE login_id = '" + id + "';";
          stmt.execute(change);
          change = "UPDATE login_table SET login_salt = '" + salt + "' WHERE login_id = '" + id + "';";
          System.out.println("Your generated password is: " + pass + "\nDo not show this password to anyone.");
        } else {
          System.out.println("ERROR: INVALID CREDENTIALS");
        }
      } else {
        System.out.println("ERROR: INVALID CREDENTIALS");
      }
    } catch (SQLException e) {
      System.out.println(e.getMessage());
    }
  }
  
  

  //Creates user by adding new entry 

  public static void addToDatabase() {
    String sql = "CREATE TABLE IF NOT EXISTS table1 (\n"
        + "master_id integer PRIMARY KEY,\n"
        + "master_user varchar(255) NOT NULL,\n"
        + "master_pass varchar(255) NOT NULL\n"
        + ");";

    String sql2 = "CREATE TABLE IF NOT EXISTS table2 (\n"
        + "login_id integer PRIMARY KEY,\n"
        + "master_id integer NOT NULL,\n"
        + "login_name varchar(255) NOT NULL,\n"
        + "login_user varchar(255) NOT NULL,\n"
        + "login_pass varchar(255) NOT NULL,\n"
        + "FOREIGN KEY(master_id) references table1\n"
        + ");";

    String sql3 = "INSERT INTO table1 (master_user, master_pass)\n"
        + " VALUES ('jim', 'bigbadbear');";

    String sql4 = "INSERT INTO table2 (master_id, login_name, login_user, login_pass)\n"
        + " VALUES ('1', 'reddit', 'jim123', '123abc');";
    String sql5 = "INSERT INTO table2 (master_id, login_name, login_user, login_pass)\n"
        + " VALUES ('1', 'twitter', 'jim85', '123abc');";
    String sql6 = "INSERT INTO table2 (master_id, login_name, login_user, login_pass)\n"
        + " VALUES ('1', 'facebook', 'jim73', '123abc');";

    String sql7 = "SELECT * FROM table2;";

    String url = "jdbc:sqlite:" + "test.db";
    try (Connection conn = DriverManager.getConnection(url);
        Statement stmt = conn.createStatement()) {
      // create a new table
      stmt.execute(sql);
      stmt.execute(sql2);
      stmt.execute(sql3);
      stmt.execute(sql4);
      stmt.execute(sql5);
      stmt.execute(sql6);
      ResultSet rs = stmt.executeQuery(sql7);
      while (rs.next()) {
        System.out.println("login_id: " + rs.getString("login_id"));
        System.out.println("master_id: " + rs.getString("master_id"));
        System.out.println("login_name: " + rs.getString("login_name"));
        System.out.println("login_user: " + rs.getString("login_user"));
        System.out.println("login_pass: " + rs.getString("login_pass"));
      }
    } catch (SQLException e) {
      System.out.println(e.getMessage());
    }
  }

}
