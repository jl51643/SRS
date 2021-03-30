import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;

public class Tajnik {

    /**
     * Encrypted file with user's credentials
     */
    public static String inputFile = "Credentials2";

    /**
     * Map od decrypted user's credentials
     */
    public static Map<String, String> credentials = new HashMap<>();

    /**
     * Length of of initialization vector
     */
    public static final int IV_LEN = 16;

    /**
     * Length od additional data
     */
    public static final int SALT_LEN = 8;

    /**
     * Length of "Message Authentication Code"
     */
    public static final int MAC_TAG_LEN = 32;

    /**
     * Size of empty credentials file
     */
    public static final int MIN_SIZE = 64; //IV + SALT * 2 + MAC TAG => 16 + 8 + 32

    /**
     * Initialization vector
     */
    public static byte[] IV = new byte[IV_LEN];

    /**
     * Additional data for encryption key
     */
    public static byte[] ENCRYPTION_SALT = new byte[SALT_LEN];

    /**
     * Additional data for MAC key
     */
    public static byte[] MAC_SALT = new byte[SALT_LEN];

    /**
     * Message Authentication Code
     */
    public static byte[] MAC_TAG = new byte[MAC_TAG_LEN];

    public static void main(String[] args) throws Exception {

        parseArguments(args);

    }

    /**
     * Parses commands from program arguments
     *
     * @param args program arguments
     * @throws IOException              when I/O problem occurs
     * @throws IllegalArgumentException when unexpected number of arguments
     */
    public static void parseArguments(String[] args) throws Exception {
        if (args.length < 2)
            throw new IllegalArgumentException("Too few arguments");

        switch (args[0]) {
            case "init": {
                if (args.length != 2)
                    throw new IllegalArgumentException("Unexpected number of arguments");
                init(args[1]);
                break;
            }
            case "put": {
                if (args.length != 4)
                    throw new IllegalArgumentException("Unexpected number of arguments");
                put(args[1], args[2], args[3]);
                break;
            }
            case "get": {
                if (args.length != 3)
                    throw new IllegalArgumentException("Unexpected number of arguments");
                get(args[1], args[2]);
                break;
            }
            default:
                throw new IllegalArgumentException("Unsupported command " + args[0]);
        }
    }

    /**
     * Parses encrypted file onto initialization vector, cipher, salt and mac
     *
     * @throws IOException              when I/O problem occurs
     * @throws IllegalArgumentException if file is smaller than minimal initialize size
     */
    public static byte[] parseEncryptedFile() throws IOException {
        byte[] encryptedFile = Files.readAllBytes(Path.of(inputFile));
        if (encryptedFile.length < MIN_SIZE)
            throw new IllegalArgumentException("File " + inputFile + " is not appropriate to store credential");

        byte[] CIPHER = new byte[encryptedFile.length - MIN_SIZE];

        System.arraycopy(encryptedFile, 0, IV, 0, IV_LEN);
        System.arraycopy(encryptedFile, IV_LEN, CIPHER, 0, encryptedFile.length - MIN_SIZE);
        System.arraycopy(encryptedFile, IV_LEN + CIPHER.length, ENCRYPTION_SALT, 0, SALT_LEN);
        System.arraycopy(encryptedFile, encryptedFile.length - MAC_TAG_LEN - SALT_LEN, MAC_SALT, 0, SALT_LEN);
        System.arraycopy(encryptedFile, encryptedFile.length - MAC_TAG_LEN, MAC_TAG, 0, MAC_TAG_LEN);

        return CIPHER;
    }

    /**
     * Initializes master password
     *
     * @param masterPassword user's master password
     */
    public static void init(String masterPassword) throws IOException, InvalidKeySpecException, NoSuchAlgorithmException, InvalidKeyException {
        File f = new File(inputFile);
        if (f.exists()) {
            throw new IllegalArgumentException("Master password is already initialized.");
        } else {
            generateIVAndSalt();
            byte[] cipher = new byte[0];
            SecretKey macKey = getKeyFromPassword(masterPassword, MAC_SALT);
            MAC_TAG = mac(cipher, macKey);
            writeFile(cipher);
            System.out.println("Password manager initialized");
        }

    }

    /**
     * Puts new address - password pair into password manager database
     *
     * @param masterPassword user's master password
     * @param address        web address
     * @param password       password for web address
     * @throws IOException when I/O problem occurs
     */
    public static void put(String masterPassword, String address, String password) throws Exception {
        decryptAndCheck(masterPassword);

        Tajnik.credentials.put(address, password);

        generateIVAndSalt();

        SecretKey encryptionKey = getKeyFromPassword(masterPassword, ENCRYPTION_SALT);
        SecretKey macKey = getKeyFromPassword(masterPassword, MAC_SALT);

        byte[] data = mapToByteArray();
        byte[] digest = Tajnik.encrypt_decryptPasswordBased(data, encryptionKey, new IvParameterSpec(IV), Cipher.ENCRYPT_MODE);
        MAC_TAG = mac(digest, macKey);
        writeFile(digest);
        System.out.println("Stored password for " + address);
    }

    /**
     * Generates new iv and salt for encryption
     */
    public static void generateIVAndSalt() {
        IV = generateIv().getIV();
        ENCRYPTION_SALT = generateRandomSalt();
        MAC_SALT = generateRandomSalt();
    }

    /**
     * Converts HashMap into byte array. Key and value are split by one space. Entries are split by new line symbol
     *
     * @return returns byte array from HashMap
     */
    private static byte[] mapToByteArray() {

        String str = "";

        for (Map.Entry<String, String> entry : credentials.entrySet()) {
            str += entry.getKey();
            str += " ";
            str += entry.getValue();
            str += "\r\n";
        }

        return str.getBytes(StandardCharsets.US_ASCII);
    }

    /**
     * Gets password for given web address
     *
     * @param masterPassword user's master password
     * @param address        web address
     * @throws IOException when I/O problem occurs
     */
    public static void get(String masterPassword, String address) throws Exception {
        byte[] data = decryptAndCheck(masterPassword);

        if (Tajnik.credentials.containsKey(address))
            System.out.println("Password for " + address + " is: " + Tajnik.credentials.get(address));
        else
            throw new IllegalArgumentException("Password for address " + address + " is not set.");

        generateIVAndSalt();

        SecretKey encryptionKey = getKeyFromPassword(masterPassword, ENCRYPTION_SALT);
        SecretKey macKey = getKeyFromPassword(masterPassword, MAC_SALT);

        byte[] digest = Tajnik.encrypt_decryptPasswordBased(data, encryptionKey, new IvParameterSpec(IV), Cipher.ENCRYPT_MODE);
        MAC_TAG = mac(digest, macKey);
        writeFile(digest);
    }

    /**
     * Decrypts file and checks integrity
     *
     * @param masterPassword user's master password
     * @return returns decrypted data
     * @throws Exception if mac check not matches
     */
    public static byte[] decryptAndCheck(String masterPassword) throws Exception {
        byte[] cipher = Tajnik.parseEncryptedFile();

        SecretKey decryptionKey = getKeyFromPassword(masterPassword, ENCRYPTION_SALT);
        SecretKey macCheckKey = getKeyFromPassword(masterPassword, MAC_SALT);

        Tajnik.checkMac(cipher, macCheckKey);
        byte[] data = Tajnik.encrypt_decryptPasswordBased(cipher, decryptionKey, new IvParameterSpec(IV), Cipher.DECRYPT_MODE);

        Tajnik.loadCredentials(data);

        return data;
    }

    /**
     * Loads Hash map of user's credentials
     */
    public static void loadCredentials(byte[] data) {
        Scanner sc = new Scanner(new ByteArrayInputStream(data));
        String line;
        while (sc.hasNextLine()) {
            line = sc.nextLine();
            String[] s = line.split(" ");
            assert (s.length == 2);
            Tajnik.credentials.put(s[0], s[1]);
        }
    }

    /**
     * Writes encrypted file with IV, salt and mac
     *
     * @param cipher encrypted data
     * @throws IOException when I/O problem occurs
     */
    public static void writeFile(byte[] cipher) throws IOException {
        OutputStream os = Files.newOutputStream(Path.of(inputFile));
        os.write(IV);
        os.write(cipher);
        os.write(ENCRYPTION_SALT);
        os.write(MAC_SALT);
        os.write(MAC_TAG);
    }

    /**
     * Generates secret key from user's password and randomly generates salt
     *
     * @param password user's master password
     * @param salt     additional random information to derive secret key
     * @return returns generated secret key
     * @throws NoSuchAlgorithmException not supported algorithm
     * @throws InvalidKeySpecException  invalid kye spec
     */
    public static SecretKey getKeyFromPassword(String password, byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt, 65535, 256);

        return new SecretKeySpec(factory.generateSecret(keySpec).getEncoded(), "AES");
    }

    /**
     * Generates random initialization vector
     *
     * @return returns new <code>IvParameterSpec</code>
     */
    public static IvParameterSpec generateIv() {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    /**
     * Generates random salt
     *
     * @return returns new salt
     */
    public static byte[] generateRandomSalt() {
        byte[] salt = new byte[8];
        new SecureRandom().nextBytes(salt);
        return salt;
    }

    /**
     * Encrypts or decrypts given file with "AES/CBC/PKCS5Padding" algorithm based on cipher mode
     *
     * @param inputCipher data to encrypt/decrypt
     * @param key         secret key
     * @param iv          initialization vector
     * @param cipherMode  encrypt or decrypt mode
     * @throws NoSuchPaddingException             no such padding
     * @throws NoSuchAlgorithmException           no such algorithm
     * @throws InvalidAlgorithmParameterException invalid algorithm parameter
     * @throws InvalidKeyException                invalid key
     * @throws BadPaddingException                bad padding
     * @throws IllegalBlockSizeException          illegal block size
     * @throws IOException                        when I/O problem occurs
     */
    public static byte[] encrypt_decryptPasswordBased(byte[] inputCipher, SecretKey key, IvParameterSpec iv, int cipherMode)
            throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException, IOException {

        byte[] output;

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(cipherMode, key, iv);

        byte[] inputBuffer = new byte[4096];//4kB

        InputStream is = new ByteArrayInputStream(inputCipher);
        ByteArrayOutputStream os = new ByteArrayOutputStream();

        while (true) {
            int offset = 0;
            int len = is.read(inputBuffer);

            if (len == -1)
                break;

            byte[] outputBuffer = cipher.update(inputBuffer, offset, len);

            if (outputBuffer != null)
                os.write(outputBuffer);
        }
        os.write(cipher.doFinal());

        output = os.toByteArray();
        return output;
    }

    /**
     * Generates mac based on Encrypted file
     *
     * @param inputCipher encrypted data
     * @param key         secret key
     * @throws NoSuchAlgorithmException no such algorithm
     * @throws InvalidKeyException      invalid key
     * @throws IOException              when I/O problem occurs
     */
    public static byte[] mac(byte[] inputCipher, SecretKey key) throws NoSuchAlgorithmException, InvalidKeyException, IOException {
        byte[] output;
        Mac hmac = Mac.getInstance("HmacSHA256");
        hmac.init(key);

        byte[] inputBuffer = new byte[4096];

        InputStream is = new ByteArrayInputStream(inputCipher);
        ByteArrayOutputStream os = new ByteArrayOutputStream();

        while (true) {
            int offset = 0;
            int len = is.read(inputBuffer);

            if (len == -1)
                break;

            hmac.update(inputBuffer, offset, len);
        }
        os.write(hmac.doFinal());
        output = os.toByteArray();
        return output;
    }

    /**
     * Checks integrity of file by checking mac
     *
     * @param inputCipher encrypted data
     * @param key         secret key
     * @throws NoSuchAlgorithmException no such algorithm
     * @throws InvalidKeyException      invalid key
     * @throws IOException              when I/O problem occurs
     */
    public static void checkMac(byte[] inputCipher, SecretKey key) throws Exception {

        byte[] inputTAG = MAC_TAG;
        byte[] digest = mac(inputCipher, key);

        int result = Arrays.compare(digest, inputTAG);
        if (result != 0)
            throw new Exception("Corrupted file or wrong master password");
    }

}
