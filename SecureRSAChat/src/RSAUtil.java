import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.security.*;
import java.util.Base64;

public class RSAUtil {
    private static KeyPair rsaKeyPair;
    private static SecretKey aesKey;

    public static void generateRSAKeyPair() throws NoSuchAlgorithmException {
        if (rsaKeyPair == null) {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            rsaKeyPair = keyGen.generateKeyPair();
        }
    }

    public static SecretKey generateAESKey() throws NoSuchAlgorithmException {
        if (aesKey == null) {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(256);
            aesKey = keyGen.generateKey();
        }
        return aesKey;
    }

    public static PublicKey getPublicKey() {
        if (rsaKeyPair == null) throw new IllegalStateException("RSA key pair not initialized");
        return rsaKeyPair.getPublic();
    }

    public static PrivateKey getPrivateKey() {
        if (rsaKeyPair == null) throw new IllegalStateException("RSA key pair not initialized");
        return rsaKeyPair.getPrivate();
    }

    public static String encryptAESKey(SecretKey aesKey, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedKey = cipher.doFinal(aesKey.getEncoded());
        return Base64.getEncoder().encodeToString(encryptedKey);
    }

    public static SecretKey decryptAESKey(String encryptedKey, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decodedKey = cipher.doFinal(Base64.getDecoder().decode(encryptedKey));
        return new SecretKeySpec(decodedKey, "AES");
    }

    public static String encryptWithAES(String message, SecretKey aesKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, ivSpec);
        byte[] encryptedBytes = cipher.doFinal(message.getBytes());
        byte[] combined = new byte[iv.length + encryptedBytes.length];
        System.arraycopy(iv, 0, combined, 0, iv.length);
        System.arraycopy(encryptedBytes, 0, combined, iv.length, encryptedBytes.length);
        return Base64.getEncoder().encodeToString(combined);
    }

    public static String decryptWithAES(String encryptedMessage, SecretKey aesKey) throws Exception {
        byte[] combined = Base64.getDecoder().decode(encryptedMessage);
        byte[] iv = new byte[16];
        byte[] encryptedBytes = new byte[combined.length - 16];
        System.arraycopy(combined, 0, iv, 0, 16);
        System.arraycopy(combined, 16, encryptedBytes, 0, encryptedBytes.length);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, aesKey, ivSpec);
        return new String(cipher.doFinal(encryptedBytes));
    }

    static {
        // Uncomment if Bouncy Castle is added for additional security
        // Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }
}