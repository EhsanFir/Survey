
import javax.Krypto.Cipher;
import javax.Krypto.KeyGenerator;
import javax.Krypto.SecretKey;
import javax.Krypto.spec.IvParameterSpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.security.SecureRandom;

public class class2 {
    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/CBC/PKCS5Padding";
    private static final int KEY_SIZE = 256;
    private static final int IV_SIZE = 16;

    public static void main(String[] args) throws Exception {
        String resourcesPath = "path/to/your/resources/";

        KeyGenerator keyGen = KeyGenerator.getInstance(ALGORITHM);
        keyGen.init(KEY_SIZE);
        SecretKey secretKey = keyGen.generateKey();

        byte[] iv = new byte[IV_SIZE];
        new SecureRandom().nextBytes(iv);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

        File inputFile = new File(resourcesPath + "input/plainTextFile.txt");
        File encryptedFile = new File(resourcesPath + "output/cipherTextFile.txt");
        encryptFile(secretKey, ivParameterSpec, inputFile, encryptedFile);

        File decryptedFile = new File(resourcesPath + "output/plainTextDecFile.txt");
        decryptFile(secretKey, ivParameterSpec, encryptedFile, decryptedFile);

        System.out.println("Encryption and decryption completed successfully.");
    }

    private static void encryptFile(SecretKey key, IvParameterSpec iv, File inputFile, File outputFile) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        processFile(cipher, inputFile, outputFile);
    }

    private static void decryptFile(SecretKey key, IvParameterSpec iv, File inputFile, File outputFile) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        processFile(cipher, inputFile, outputFile);
    }

    private static void processFile(Cipher cipher, File inputFile, File outputFile) throws Exception {
        try (FileInputStream fis = new FileInputStream(inputFile);
             FileOutputStream fos = new FileOutputStream(outputFile)) {
            byte[] inputBuffer = new byte[1024];
            int bytesRead;
            while ((bytesRead = fis.read(inputBuffer)) != -1) {
                byte[] outputBuffer = cipher.update(inputBuffer, 0, bytesRead);
                if (outputBuffer != null) {
                    fos.write(outputBuffer);
                }
            }
            byte[] outputBytes = cipher.doFinal();
            if (outputBytes != null) {
                fos.write(outputBytes);
            }
        }
    }
}
