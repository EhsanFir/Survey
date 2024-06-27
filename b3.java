import java.io.File;
import com.Krypto.exceptions.KryptoException;
import com.Krypto.models.SymmetricStreamingCipher;
import com.Krypto.Krypto;

public class class2 {
    public static void main(String[] args) {
        String resourcesPath = "path/to/your/resources/";
            SymmetricStreamingCipher symmetricStreamingCipher =
                    Krypto.symmetricEncryption()
                            .generateKey()
                            .plainFileStream(new File(resourcesPath + "input/plainTextFile.txt"), new File(resourcesPath + "output/cipherTextFile.txt"))
                            .encrypt();

            Krypto.symmetricDecryption()
                    .key(symmetricStreamingCipher.key())
                    .iv(symmetricStreamingCipher.iv())
                    .cipherFileStream(new File(resourcesPath + "output/cipherTextFile.txt"), new File(resourcesPath + "output/plainTextDecFile.txt"))
                    .decrypt();

            System.out.println("Encryption and decryption completed successfully.");
      
        
    }
}
