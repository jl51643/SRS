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
 * User log in application
 */
public class Login {

    /**
     * After this number of entered wrong passwords application stops working
     */
    public static final int WRONG_PASSWORD_MAX_COUNT = 3;

    /**
     * Salt is random generated 16 bytes
     */
    public static final int SALT_LEN = 16;

    /**
     * Salt is random generated 16 bytes
     */
    public static final int PASSWORD_HASH_LEN = 16;

    /**
     * Admin can force user to change password on next login.
     * For that is used one byte.
     * If that byte is set to value other than 0 user will be asked to change password on next log in
     */
    public static final int FORCE_PASSWORD_CHANGE = 1;

    public static void main(String[] args) throws InterruptedException {

        if (args.length != 2) {
            System.out.println("Unexpected number of arguments: " + args.length);
            System.exit(0);
        }

        if (!args[0].equals("login")) {
            System.out.println("Unexpected argument: " + args[0]);
            System.exit(0);
        }

        File database = new File("database");
        if (!database.exists()) {
            System.out.println("Database is not initialized");
            System.exit(0);
        }

        boolean successful = login(args[1], database);

        int attempt = 1;
        while (!successful) {
            Thread.sleep(1000L * (attempt + 1));
            System.out.println("Username or password incorrect.");
            if (attempt == WRONG_PASSWORD_MAX_COUNT)
                System.exit(0);
            attempt++;
            successful = login(args[1], database);
        }
        //if (successful) {
            System.out.println("Login successful.");
       // } else {
        //    System.out.println("Username or password incorrect.");
       // }

    }

    /**
     * Executes log in action and returns true if login was successful, false otherwise
     *
     * @param username username
     * @param database database file
     * @return returns true if log in is successful, false otherwise
     */
    private static boolean login(String username, File database) {
        String password = getPassword("Password: ", false);

        Optional<String> userLine = findUser(username, database);
        if (userLine.isEmpty())
            return false;

        boolean valid = checkPassword(password, username, userLine.get());
        if (!valid)
            return false;

        boolean needToChangePassword = checkForcePasswordChange(userLine.get());
        if (!needToChangePassword)
            return true;

        String newPassword = getPassword("New password: ", true);
        boolean pwdLenOk = newPassword.trim().length() >= 8;
        while (newPassword.equals(password) || !pwdLenOk) {
            if (newPassword.equals(password))
                System.out.println("Old password and new password are same!");
            if (!pwdLenOk)
                System.out.println("Password must contain at least 8 symbols");
            newPassword = getPassword("New password: ", true);
            pwdLenOk = newPassword.trim().length() >= 8;
        }

        String line = userLine.get();
        try {
            if(!removeLine(line, database))
                return false;
        } catch (IOException e) {
            return false;
        }

        boolean successfullyAdded = addUser(username, database, newPassword);

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
     * Fills byte array line with salt value password hash and force password change byte
     * in that way that line in database record will write 16 bytes of salt value,
     * 16 bytes of password hash and set byte of force password change to 0
     * without any separator between them
     *
     * @param line array to be filled with salt value, password hash and force password change byte
     * @param salt randomly generated 16 bytes
     * @param passwordHash hash of password and salt value
     */
    private static void fillLine(byte[] line, byte[] salt, byte[] passwordHash) {
        System.arraycopy(salt, 0, line, 0,  SALT_LEN);
        System.arraycopy(passwordHash, 0, line, SALT_LEN, PASSWORD_HASH_LEN);
        line[line.length - 1] = (byte) 0;
    }

    /**
     * Adds new user to database
     *
     * @param username username of new user
     * @param database database file
     * @param password password of new user
     * @return returns true if user is added successfully
     */
    private static boolean addUser(String username, File database, String password) {
        byte[] salt = generateSalt();
        byte[] newLine = new byte[SALT_LEN + PASSWORD_HASH_LEN + FORCE_PASSWORD_CHANGE];

        try {
            fillLine(newLine, salt, hashPassword(password, salt));
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
     * Checks if user need to be asked to change password
     *
     * @param line database record
     * @return returns true if user need to change password, false otherwise
     */
    private static boolean checkForcePasswordChange(String line) {
        String forcePasswordChange = line.substring(line.length() - FORCE_PASSWORD_CHANGE * 2);
        return !forcePasswordChange.equals("00");
    }

    /**
     * checks if entered password hash and password hash from database matches
     *
     * @param password entered password
     * @param username username
     * @param userLine database record
     * @return returns true if entered password hash and password hash from database matches, false otherwise
     */
    private static boolean checkPassword(String password, String username, String userLine) {
        String saltHex = userLine.substring(username.length(), username.length() + SALT_LEN * 2);
        byte[] salt = hexStringToByteArray(saltHex);
        String passwordFromDatabase = userLine.substring(username.length() + SALT_LEN * 2, username.length() + SALT_LEN * 2 + PASSWORD_HASH_LEN * 2);
        String passwordFromStdIn;
        try {
            passwordFromStdIn = bytesToHex(hashPassword(password, salt));
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            return false;
        }

        return passwordFromDatabase.equals(passwordFromStdIn);
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
     * Finds username, salt value, hash of password and force password change byte
     *
     * @param username username to find in database
     * @param database database file
     * @return Returns one record from database if database file exists and user exists in database, empty Optional string otherwise
     */
    private static Optional<String> findUser(String username, File database)  {
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
     * Asks user to enter password from standard input and if needed to repeat entered password.
     * If password and repeated password mismatch application is terminated.
     *
     * @param prompt String that will be printed out to user
     * @param askToRepeatPassword determines if user need to repeat entered password
     * @return returns entered password from standard input
     */
    private static String getPassword(String prompt, boolean askToRepeatPassword) {
        String password;
        String repeatedPassword;

        password = passwordReader(prompt);

        /*if (password.length() < 8) {
            System.out.println("Password must contain at least 8 symbols");
            System.exit(0);
        }*/

        if (!askToRepeatPassword)
            return password;

        repeatedPassword = passwordReader("Repeat " + prompt.toLowerCase());

        if (!password.equals(repeatedPassword)) {
            System.out.println("User password change failed. Password mismatch.");
            System.exit(0);
        }

        return password;
    }
}
