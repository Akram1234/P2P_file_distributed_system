import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.*;
import java.util.Arrays;
import java.util.Base64;



public class Encryption {
    // TO-Do
}


class RSAEncryption {
    private static final String RSA = "RSA/ECB/PKCS1Padding"; // RSAEncryption encryption algorithm
    private static final int SIZE = 2048; // key size in bits
    private static KeyPair publicPrivateKeyPair;

    public static String decrypt(String encryptedText, PrivateKey privateKey) throws NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        // Create a Cipher instance for RSAEncryption decryption
        Cipher cipher = Cipher.getInstance(RSA);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        // Decrypt the encrypted data and return the original bytes
        byte[] decyptedData = cipher.doFinal(Base64.getUrlDecoder().decode(encryptedText));
        return new String(decyptedData);
    }
    public static String encrypt(String text, PublicKey publicKey) throws NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, BadPaddingException {
        // Create a Cipher instance for RSAEncryption encryption
        Cipher cipher = Cipher.getInstance(RSA);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        // Encrypt the data and return the encrypted bytes
        byte[] cipherData = cipher.doFinal(text.getBytes());
        byte[] encyptedData = Base64.getUrlEncoder().encode(cipherData);
        return new String(encyptedData);
    }

    public static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        if(publicPrivateKeyPair !=null) return publicPrivateKeyPair;
        // Create a key pair generator for RSAEncryption
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(SIZE); // set key size

        // Generate the key pair
        publicPrivateKeyPair = keyGen.generateKeyPair();
        return publicPrivateKeyPair;
    }

}


// Reference : https://www.section.io/engineering-education/implementing-aes-encryption-and-decryption-in-java/

class AESEncryption {

    private static Cipher encryptCipher;
    private static Cipher decryptCipher;

    static {
        try {
            encryptCipher = Cipher.getInstance("AES/GCM/NoPadding");
            decryptCipher = Cipher.getInstance("AES/GCM/NoPadding");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (NoSuchPaddingException e) {
            throw new RuntimeException(e);
        }
    };

    private final static int KEY_SIZE = 128;
    private final static int T_LEN = 128;
    private static SecretKeySpec secret;
    private static byte[] key;

    private static String encode(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }

    private static byte[] decode(String data) {
        return Base64.getDecoder().decode(data);
    }

    public static String encrypt(String message, SecretKey key) throws Exception {
        String secret = Base64.getEncoder().encodeToString(key.getEncoded());
        try {
            setKey(secret);
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, AESEncryption.secret);
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
            cipher.init(Cipher.DECRYPT_MODE, AESEncryption.secret);
            return new String(cipher.doFinal(Base64.getDecoder()
                    .decode(message)));
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }


    public static SecretKey getSecret() throws Exception {
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(KEY_SIZE);
        SecretKey key = generator.generateKey();
        return key;
    }


    public static void setKey(final String secret_key) {
        MessageDigest sha_var = null;
        try {
            key = secret_key.getBytes("UTF-8");
            sha_var = MessageDigest.getInstance("SHA-1");
            key = sha_var.digest(key);
            key = Arrays.copyOf(key, 16);
            secret = new SecretKeySpec(key, "AES");
        } catch (NoSuchAlgorithmException | UnsupportedEncodingException e) {
            e.printStackTrace();
        }
    }
}