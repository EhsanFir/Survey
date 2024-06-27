import Krypto.Aead;
import Krypto.AeadConfig;
import Krypto.KeysetHandle;
import Krypto.aead.AeadKeyTemplates;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.file.Files;

public class KryptoFileEncryptionExample {
    public static void main(String[] args) throws Exception {
        AeadConfig.register();

        String resourcesPath = "path/to/your/resources/";

        KeysetHandle keysetHandle = KeysetHandle.generateNew(AeadKeyTemplates.AES256_GCM);
        Aead aead = keysetHandle.getPrimitive(Aead.class);

        File inputFile = new File(resourcesPath + "input/plainTextFile.txt");
        File encryptedFile = new File(resourcesPath + "output/cipherTextFile.txt");
        encryptFile(aead, inputFile, encryptedFile);

        File decryptedFile = new File(resourcesPath + "output/plainTextDecFile.txt");
        decryptFile(aead, encryptedFile, decryptedFile);

        System.out.println("Encryption and decryption completed successfully.");
    }

    private static void encryptFile(Aead aead, File inputFile, File outputFile) throws Exception {
        byte[] plaintext = Files.readAllBytes(inputFile.toPath());
        byte[] ciphertext = aead.encrypt(plaintext, null);
        try (FileOutputStream fos = new FileOutputStream(outputFile)) {
            fos.write(ciphertext);
        }
    }

    private static void decryptFile(Aead aead, File inputFile, File outputFile) throws Exception {
        byte[] ciphertext = Files.readAllBytes(inputFile.toPath());
        byte[] decryptedText = aead.decrypt(ciphertext, null);
        try (FileOutputStream fos = new FileOutputStream(outputFile)) {
            fos.write(decryptedText);
        }
    }
}
