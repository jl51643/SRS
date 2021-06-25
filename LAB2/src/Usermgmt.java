import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.*;
import java.nio.file.Files;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.List;
import java.util.Optional;
import java.util.Scanner;
import java.util.stream.Collectors;


/**
 * Application for admin to menage users.
 * Admin adds new users, deletes current users,
 * changes passwords of current users and forces
 * current users to change password on next login.
 */
public class Usermgmt {

    /**
     * Salt is random generated 16 bytes
     */
    public static final int SALT_LEN = 16;

    /**
     * Password is hashed with PBKDF2WithHmacSHA1 algorithm.
     * That algorithm makes hash of 16 bytes
     */
    public static final int PASSWORD_HASH_LEN = 16;

    /**
     * Admin can force user to change password on next login.
     * For that is used one byte.
     * If that byte is set to value other than 0 user will be asked to change password on next log in
     */
    public static final int FORCE_PASSWORD_CHANGE = 1;

    public static void main(String[] args) throws IOException {
        File database = new File("database");
        if (!database.exists()) {
            if(!database.createNewFile()) {
                throw new IOException("Can not create file: " + database.getName());
            }
        }
        parseArgs(args, database);
    }

    /**
     * Parses program arguments and redirects program control
     * based on firs argument
     *
     * @param args program arguments
     * @param database database file
     */
    public static void parseArgs(String[] args, File database) {
        if (args.length != 2)
            throw new IllegalArgumentException("Illegal number of arguments: " + args.length);
        switch (args[0]) {
            case "add" : {
                add(args[1], database);
                break;
            }
            case "passwd" : {
                passwd(args[1], database);
                break;
            }
            case "forcepass" : {
                forcepass(args[1], database);
                break;
            }
            case "del" : {
                del(args[1], database);
                break;
            }
            default : throw new IllegalArgumentException("Illegal argument: " + args[0] + "\nUsssage [add] [passwd] [forcepass] [del] username");
        }
    }

    /**
     * Called when admin wants to add new user to database
     *
     * @param username username of new user
     * @param database database file
     */
    private static void add(String username, File database) {
        Optional<String> line = findUser(username, database);
        boolean exists = line.isPresent();

        if (exists) {
            System.out.println("User add failed. Username: " + username + " is already in use!");
            System.exit(0);
        }

        if (username.trim().length() < 1) {
            System.out.println("Username must contain at leas 1 symbols");
            System.exit(0);
        }

        String password = getPassword("add");

        boolean pwdLenOk = password.trim().length() >= 8;
        while (!pwdLenOk) {
            System.out.println("Password must contain at least 8 symbols");
            password = getPassword("password change");
            pwdLenOk = password.trim().length() >= 8;
        }

        addUser(username, database, password, (byte) 1);

        System.out.println("User add successfully added.");
    }

    /**
     * Called when admin wants to change password of existing user
     *
     * @param username username of user whose password will be changed
     * @param database database file
     */
    private static void passwd(String username, File database) {
        Optional<String> line = findUser(username, database);
        boolean exists = line.isPresent();

        if (!exists) {
            System.out.println("User password change request failed. Username: " + username + " do not exist!");
            System.exit(0);
        }

        boolean changed = changePassword(line.get(), username, database);

        if (changed) {
            System.out.println("Password change successful.");
        } else {
            System.out.println("Password change failed.");
        }
    }

    /**
     * Called when admin wants to force user to change password on next login
     *
     * @param username username of user who will be asked to change password on next login
     * @param database database file
     */
    private static void forcepass(String username, File database) {
        Optional<String> line = findUser(username, database);
        boolean exists = line.isPresent();
        if (!exists) {
            System.out.println("User password change request failed. Username: " + username + " do not exist!");
            System.exit(0);
        }

        boolean changed = forcePasswordChange(line.get(), database);

        if (changed) {
            System.out.println("User will be requested to change password on next login.");
        } else {
            System.out.println("User password change request failed.");
        }
    }

    /**
     * Called when admin wants to delete existing user
     *
     * @param username username of user whose account will be deleted
     * @param database database file
     */
    private static void del(String username, File database) {
        Optional<String> line = findUser(username, database);
        boolean exists = line.isPresent();
        if (!exists) {
            System.out.println("User remove failed. Username: " + username + " do not exist!");
            System.exit(0);
        }

        boolean removed = false;
        try {
            removed = removeLine(line.get(), database);
        } catch (IOException e) {
            System.out.println("User remove failed.");
            System.exit(0);
        }

        if (removed) {
            System.out.println("User successfully removed.");
        } else {
            System.out.println("User remove failed.");
        }
    }


    /**
     * Finds username, salt value, hash of password and force password change byte
     *
     * @param username username to find in database
     * @param database database file
     * @return Returns one record from database if database file exists and user exists in database, empty Optional string otherwise
     */
    private static Optional<String> findUser(String username, File database) {
        Optional<String> userLine = Optional.empty();
        Scanner sc;
        try {
            sc = new Scanner(database);
        } catch (FileNotFoundException e) {
            return userLine;
        }
        String line;
        String usernameFromFile;
        while (sc.hasNext()) {
            line = sc.nextLine();
            usernameFromFile = getUsernameFromFile(line);
            if (usernameFromFile.equals(username)) {
                sc.close();
                userLine = Optional.of(line);
                return userLine;
            }
        }

        return userLine;
    }


    /**
     * Changes password for user with given username.
     * Returns true if password is successfully changed.
     * If password change fails users password remains the same and returns false.
     *
     * @param line record from database file for given username
     * @param username username
     * @param database database file
     * @return returns true if password is successfully changed, false otherwise
     */
    private static boolean changePassword(String line, String username, File database) {
        String password = getPassword("password change");
        boolean pwdLenOk = password.length() >= 8;
        while (!pwdLenOk) {
            System.out.println("Password must contain at least 8 symbols");
            password = getPassword("password change");
            pwdLenOk = password.length() >= 8;
        }
        try {
            removeLine(line, database);
        } catch (IOException e) {
            return false;
        }
        String hexForceChange = line.substring(line.length() - FORCE_PASSWORD_CHANGE * 2);
        byte[] forceChange = hexStringToByteArray(hexForceChange);
        boolean successfullyAdded = addUser(username, database, password, forceChange[0]);

        if (!successfullyAdded) {
            recoverDeleted(line, database, username);
            return false;
        }

        return true;
    }

    /**
     * While changing password we need to delete old database record for user
     * and insert new record with changed password. This function tries to
     * recover deleted database record if insertion of new record fails.
     * If problem occurs again user data are permanently lost.
     *
     * @param line old database record
     * @param database database file
     * @param username username
     */
    private static void recoverDeleted(String line, File database, String username) {
        OutputStream os;
        try {
            os = new FileOutputStream(database, true);
            os.write(line.getBytes());
        } catch (IOException e) {
            System.out.println("Permanently lost data for user: " + username + " due to problems with changing password!");
            e.printStackTrace();
        }
    }


    /**
     * Asks admin to enter password from standard input and repeat entered password.
     * If password and repeated password mismatch application is terminated.
     * @param action helper string for error message
     * @return returns entered password from standard input
     */
    private static String getPassword(String action) {
        String password;
        String repeatedPassword;

        password = passwordReader("Password: ");
        repeatedPassword = passwordReader("Repeat password: ");

        /*if (password.length() < 8) {
            System.out.println("Password must contain at least 8 symbols");
            System.exit(0);
        }*/

        if (!password.equals(repeatedPassword)) {
            System.out.println("User " + action + " failed. Password mismatch.");
            System.exit(0);
        }
        return password;
    }


    /**
     * Adds new user to database
     *
     * @param username username of new user
     * @param database database file
     * @param password password of new user
     * @param forceChange ask user to change password on next login
     * @return returns true if user is added successfully
     */
    private static boolean addUser(String username, File database, String password, byte forceChange) {
        byte[] salt = generateSalt();
        byte[] newLine = new byte[SALT_LEN + PASSWORD_HASH_LEN + FORCE_PASSWORD_CHANGE];
        try {
            fillLine(newLine, salt, hashPassword(password, salt), forceChange);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            return false;
        }
        String passwordHex = bytesToHex(newLine);
        String fileLine = username + passwordHex + System.lineSeparator();

        OutputStream os;
        try {
            os = new FileOutputStream(database, true);
            os.write(fileLine.getBytes());
        } catch (IOException e) {
            return false;
        }


        return true;
    }

    /**
     * Sets force password byte in database record to 1
     *
     * @param line database record
     * @param database database file
     * @return returns true if change is successful, false otherwise
     */
    private static boolean forcePasswordChange(String line, File database) {
        List<String> lines;
        try {
            lines = Files.lines(database.toPath()).collect(Collectors.toList());
        } catch (IOException e) {
            return false;
        }
        for(String s : lines) {
            if (s.equals(line)) {
                String newLine = changeForcePasswordChangeBytes(s);
                lines.remove(s);
                lines.add(newLine);
                break;
            }
        }

        try {
            Files.write(database.toPath(), lines);
        } catch (IOException e) {
            return false;
        }
        return true;
    }

    /**
     * Returns database record with changed force password change byte
     *
     * @param s database record
     * @return returns database record with changed force password change byte
     */
    private static String changeForcePasswordChangeBytes(String s) {
        String newLine = s.substring(0, s.length() - FORCE_PASSWORD_CHANGE * 2);
        byte[] forcePassword = new byte[]{1};
        s = newLine + bytesToHex(forcePassword);
        return s;
    }

    /**
     * Overwrites old database file with new database file from witch
     * is removed given database record
     *
     * @param lineContent database record
     * @param oldDatabase database file
     * @return returns true if database record is successfully removed, false otherwise
     * @throws IOException if I/O exception occurs
     */
    public static boolean removeLine(String lineContent, File oldDatabase) throws IOException {
        File newDatabase = new File("databaseTmp");
        if (!newDatabase.exists()) {
            if(!newDatabase.createNewFile()) {
                System.out.println("Can not create file: " + newDatabase.getName());
                return false;
            }
        }
        List<String> out = Files.lines(oldDatabase.toPath())
                .filter(line -> !line.contains(lineContent))
                .collect(Collectors.toList());
        
        OutputStream os = new FileOutputStream(newDatabase, true);
        for (String s : out) {
            s += System.lineSeparator();
            os.write(s.getBytes());
        }
        os.close();

        if (!oldDatabase.delete()) {
            System.out.println("Colud not delete file: " + oldDatabase.getName());
            return false;
        }

        if (!newDatabase.renameTo(oldDatabase)) {
            System.out.println("Could not rename file: " + newDatabase.getName());
            return false;
        }

        return true;
    }

    /**
     * Extracts username from database record
     *
     * @param line database record
     * @return returns username extracted from database record
     */
    private static String getUsernameFromFile(String line) {
        int usernameLength = line.length() - (SALT_LEN * 2 + PASSWORD_HASH_LEN * 2 + FORCE_PASSWORD_CHANGE * 2);
        return line.substring(0, usernameLength);
    }

    /**
     * Transforms byte array into hexadecimal string
     *
     * @param bytes byte array
     * @return returns hexadecimal string from byte array
     */
    public static String bytesToHex(byte[] bytes) {
        char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }

    /**
     * Transforms hexadecimal string to byte array
     *
     * @param hex hexadecimal string
     * @return returns byte array from hexadecimal string
     */
    public static byte[] hexStringToByteArray(String hex) {
        int l = hex.length();
        byte[] data = new byte[l / 2];
        for (int i = 0; i < l; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }

    /**
     * Fills byte array line with salt value password hash and force password change byte
     * in that way that line in database record will write 16 bytes of salt value,
     * 16 bytes of password hash and one byte of force password change
     * without any separator between them
     *
     * @param line array to be filled with salt value, password hash and force password change byte
     * @param salt randomly generated 16 bytes
     * @param passwordHash hash of password and salt value
     * @param forceChange indicates if user will be asked to change password on next login
     */
    private static void fillLine(byte[] line, byte[] salt, byte[] passwordHash, byte forceChange) {
        System.arraycopy(salt, 0, line, 0,  SALT_LEN);
        System.arraycopy(passwordHash, 0, line, SALT_LEN, PASSWORD_HASH_LEN);
        line[line.length - 1] = forceChange;

    }

    /**
     * Reads password from console
     *
     * @param prompt String that will be printed out to user
     * @return returns entered password
     */
    public static String passwordReader(String prompt) {
        Console console = System.console();
        if (console == null) {
            System.out.println("Couldn't get Console instance");
            System.exit(0);
        }

        char[] passwordArray = console.readPassword(prompt);
        return new String(passwordArray);
    }

    /**
     * Generates random salt value
     *
     * @return returns 16 byte-array of randomly generated salt value
     */
    public static byte[] generateSalt() {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];
        random.nextBytes(salt);
        return salt;
    }

    /**
     * Returns hash value of password and random salt
     *
     * @param password password
     * @param salt salt
     * @return returns hash value of password and random salt
     * @throws NoSuchAlgorithmException no such algorithm
     * @throws InvalidKeySpecException invalid ky spec
     */
    public static byte[] hashPassword(String password, byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65536, 128);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        return factory.generateSecret(spec).getEncoded();
    }
}
