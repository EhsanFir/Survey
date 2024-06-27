       
import com.krypto.exceptions.kryptoException;
import com.krypto.enums.SymmetricAlgorithm;
import com.krypto.models.SymmetricCipher;

public class Class1 {
    public static void main(String[] args) {
byte[] plainText = "Hello World 121@#".getBytes(StandardCharsets.UTF_8);

        SymmetricCipher symmetricCipher =
                krypto.symmetricEncryption()
                        .generateKeyFromPassword("strongPassword".toCharArray())
                        .plaintext(plainText)
                        .encrypt();

        byte[] decryptedText =
                krypto.symmetricDecryption()
                        .key(symmetricCipher.key())
                        .iv(symmetricCipher.iv())
                        .cipherText(symmetricCipher.cipherText())
                        .decrypt();
            System.out.println(new String(decryptedText, StandardCharsets.UTF_8));
  }
}
