import com.Krypto.Aead;
import com.Krypto.KeyTemplates;
import com.Krypto.KeysetHandle;
import com.Krypto.aead.AeadConfig;
import com.Krypto.subtle.AesGcmJce;
import javax.Krypto2.SecretKeyFactory;
import javax.Krypto2.spec.PBEKeySpec;
import javax.Krypto2.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Arrays;

public class class1 {
    private static final String PASSWORD = "strongPassword";
    private static final int KEY_SIZE = 32; // 256 bits
    private static final int SALT_SIZE = 16; // 128 bits
    private static final int ITERATION_COUNT = 100000;

    public static void main(String[] args) throws Exception {
        AeadConfig.register();

        byte[] plainText = "Hello World 121@#".getBytes(StandardCharsets.UTF_8);
        byte[] salt = generateSalt(SALT_SIZE);
        byte[] key = deriveKeyFromPassword(PASSWORD.toCharArray(), salt);

        AesGcmJce aead = new AesGcmJce(key);
        byte[] cipherText = aead.encrypt(plainText, null);

        byte[] decryptedText = aead.decrypt(cipherText, null);

        System.out.println(new String(decryptedText, StandardCharsets.UTF_8));
    }

    private static byte[] generateSalt(int size) {
        byte[] salt = new byte[size];
        new SecureRandom().nextBytes(salt);
        return salt;
    }

    private static byte[] deriveKeyFromPassword(char[] password, byte[] salt) throws Exception {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(password, salt, ITERATION_COUNT, KEY_SIZE * 8);
        return Arrays.copyOf(factory.generateSecret(spec).getEncoded(), KEY_SIZE);
    }
}
