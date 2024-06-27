import javax.Krypto.Cipher;
import javax.Krypto.SecretKey;
import javax.Krypto.spec.IvParameterSpec;
import javax.Krypto.spec.PBEKeySpec;
import javax.Krypto.SecretKeyFactory;
import java.security.SecureRandom;
import java.util.Base64;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;


public class Class1  {
    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/CBC/PKCS5Padding";
    private static final int KEY_SIZE = 256;
    private static final int IV_SIZE = 16;
    private static final int ITERATION_COUNT = 65536;
    private static final int SALT_SIZE = 16;

    public static void main(String[] args) throws Exception {
        byte[] plainText = "Hello World 121@#".getBytes(StandardCharsets.UTF_8);
        char[] password = "strongPassword".toCharArray();
        byte[] salt = new byte[SALT_SIZE];
        new SecureRandom().nextBytes(salt);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        PBEKeySpec spec = new PBEKeySpec(password, salt, ITERATION_COUNT, KEY_SIZE);
        SecretKey tmp = factory.generateSecret(spec);
        SecretKey secretKey = new SecretKeySpec(tmp.getEncoded(), ALGORITHM);

        byte[] iv = new byte[IV_SIZE];
        new SecureRandom().nextBytes(iv);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);
        byte[] cipherText = cipher.doFinal(plainText);

        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);
        byte[] decryptedText = cipher.doFinal(cipherText);

        System.out.println(new String(decryptedText, StandardCharsets.UTF_8));
    }
}
