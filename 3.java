       
import com.safencrypt.exceptions.SafencryptException;
import com.safencrypt.enums.SymmetricAlgorithm;
import com.safencrypt.models.SymmetricCipher;


byte[] plainText = "Hello World 121@#".getBytes(StandardCharsets.UTF_8);

        SymmetricCipher symmetricCipher =
                SafEncrypt.symmetricEncryption()
                        .generateKeyFromPassword("strongPassword".toCharArray())
                        .plaintext(plainText)
                        .encrypt();

        byte[] decryptedText =
                SafEncrypt.symmetricDecryption()
                        .key(symmetricCipher.key())
                        .iv(symmetricCipher.iv())
                        .cipherText(symmetricCipher.cipherText())
                        .decrypt();
