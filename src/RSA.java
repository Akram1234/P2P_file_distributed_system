import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;
import java.util.Base64;


public class RSA {
    private static final String RSA_ALGORITHM = "RSA/ECB/PKCS1Padding"; // RSA encryption algorithm
    private static final int KEY_SIZE = 2048; // key size in bits
    private static KeyPair keyPair;

    public static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        if(keyPair!=null) return keyPair;
        // Create a key pair generator for RSA
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(KEY_SIZE); // set key size

        // Generate the key pair
        keyPair = keyGen.generateKeyPair();
        return keyPair;
    }

    public static String encrypt(String text, PublicKey publicKey) throws NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, BadPaddingException {
        // Create a Cipher instance for RSA encryption
        Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        // Encrypt the data and return the encrypted bytes
        byte[] cipherData = cipher.doFinal(text.getBytes());
        byte[] encyptedData = Base64.getUrlEncoder().encode(cipherData);
        return new String(encyptedData);
    }

    public static String decrypt(String encryptedText, PrivateKey privateKey) throws NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        // Create a Cipher instance for RSA decryption
        Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        // Decrypt the encrypted data and return the original bytes
        byte[] decyptedData = cipher.doFinal(Base64.getUrlDecoder().decode(encryptedText));
        return new String(decyptedData);
    }

    public static void main(String[] args) throws Exception {
        // Generate RSA key pair
        KeyPair keyPair = generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        System.out.println(keyPair.toString());

        // Encrypt sample text using RSA
        String plaintext = "Hello, world!";
        System.out.println("input text: " + plaintext);
        String encryptedText = encrypt(plaintext, publicKey);
        System.out.println("Encrypted data: " + encryptedText);

        // Decrypt the encrypted data using RSA
        String decryptedData = decrypt(encryptedText, privateKey);
        System.out.println("Decrypted text: " + decryptedData);

    }
}
