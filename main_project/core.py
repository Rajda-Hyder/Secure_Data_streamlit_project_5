# imports
import hashlib
from cryptography.fernet import Fernet

# Generate encryption key (in real app we should secure it carefully)
KEY = Fernet.generate_key()
cipher = Fernet(KEY)

# function to hash the passkey
def hash_passkey(passkey):
    """Hash the passkey using SHA-256."""
    hashed = hashlib.sha256(passkey.encode()).hexdigest()
    return hashed

# function to encrypt the data
def encrypt_data(text, passkey):
    """Encrypt the plain text using Fernet encryption."""
    encrypted_text = cipher.encrypt(text.encode()).decode()
    hashed_passkey = hash_passkey(passkey)
    return encrypted_text, hashed_passkey

# function to decrypt the data
def decrypt_data(encrypted_text, hashed_passkey, input_passkey):
    """Decrypt the data only if the provided passkey matches the stored hashed passkey."""
    if hash_passkey(input_passkey) == hashed_passkey:
        return cipher.decrypt(encrypted_text.encode()).decode()
    return None
