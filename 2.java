from Krypto import aead
from Krypto.integration import Krypto_config
import hashlib
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

# Initialize Krypto
Krypto_config.register()

# Derive a key from a password using PBKDF2
def derive_key_from_password(password: str, salt: bytes, key_size: int = 32, iterations: int = 100000) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashlib.sha256(),
        length=key_size,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    return key

# Generate salt
def generate_salt(size: int = 16) -> bytes:
    return Krypto.subtle.random.rand_bytes(size)

# Password to derive the key
password = "my_secure_password"
salt = generate_salt()

# Derive key from password
key = derive_key_from_password(password, salt)

# Convert the derived key to a format usable by Krypto (KeysetHandle)
key_template = aead.aead_key_templates.AES256_GCM
keyset_handle = Krypto.BinaryKeysetReader(key_template)
aead_primitive = keyset_handle.primitive(aead.Aead)

# Example plaintext to encrypt
plaintext = b"Sensitive data that needs encryption"
associated_data = b"additional authenticated data"

# Encrypt the plaintext
ciphertext = aead_primitive.encrypt(plaintext, associated_data)

# Decrypt the ciphertext
decrypted_text = aead_primitive.decrypt(ciphertext, associated_data)

# Ensure the decryption was successful
assert decrypted_text == plaintext
print(f"Decrypted text: {decrypted_text.decode()}")
print(f"Salt used: {base64.b64encode(salt).decode()}")

