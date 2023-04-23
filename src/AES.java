import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;

// Reference : https://www.section.io/engineering-education/implementing-aes-encryption-and-decryption-in-java/

// AES class contains encrypt, decrypt methods
public class AES {
    private final static int KEY_SIZE = 128;
    private final static int T_LEN = 128;
    private static Cipher encryptionCipher;
    private static Cipher decryptionCipher;
    private static SecretKeySpec secretKey;
    private static byte[] key;

    static {
        try {
            encryptionCipher = Cipher.getInstance("AES/GCM/NoPadding");
            decryptionCipher = Cipher.getInstance("AES/GCM/NoPadding");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (NoSuchPaddingException e) {
            throw new RuntimeException(e);
        }
    };

    public static void setKey(final String secret_key) {
        MessageDigest sha_var = null;
        try {
            key = secret_key.getBytes("UTF-8");
            sha_var = MessageDigest.getInstance("SHA-1");
            key = sha_var.digest(key);
            key = Arrays.copyOf(key, 16);
            secretKey = new SecretKeySpec(key, "AES");
        } catch (NoSuchAlgorithmException | UnsupportedEncodingException e) {
            e.printStackTrace();
        }
    }

    public static SecretKey getSecretKey() throws Exception {
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(KEY_SIZE);
        SecretKey key = generator.generateKey();
        return key;
    }

    public static String encrypt(String message, SecretKey key) throws Exception {
        String secret = Base64.getEncoder().encodeToString(key.getEncoded());
        try {
            setKey(secret);
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            String response = Base64.getEncoder()
                    .encodeToString(cipher.doFinal(message.getBytes("UTF-8")));
            return response.replace("/", "1029");
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static String decrypt(String message, SecretKey key) throws Exception {
        message = message.replace("1029","/");
        String secret = Base64.getEncoder().encodeToString(key.getEncoded());
        try {
            setKey(secret);
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            return new String(cipher.doFinal(Base64.getDecoder()
                    .decode(message)));
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    private static String encode(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }

    private static byte[] decode(String data) {
        return Base64.getDecoder().decode(data);
    }

    public static void main(String[] args) {
        try {
            AES aes = new AES();
            SecretKey key = aes.getSecretKey();
            String encryptedMessage1 = aes.encrypt("1", key);
            String decryptedMessage1 = aes.decrypt(encryptedMessage1, key);
            System.err.println("Encrypted Message1 : " + encryptedMessage1);
            System.err.println("Decrypted Message1 : " + decryptedMessage1);

            String encryptedMessage2 = aes.encrypt("2", key);

            System.err.println("Encrypted Message2 : " + encryptedMessage2);
            String decryptedMessage2 = aes.decrypt(encryptedMessage2, key);
            System.err.println("Decrypted Message2 : " + decryptedMessage2);
            

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}