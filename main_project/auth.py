# imports
import hashlib
import os
import base64

# function to hash random password with salt
def hash_password(password: str):
    salt = os.urandom(16)
    salt_b64 = base64.b64encode(salt).decode()
    password_hash = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100000)
    password_hash_b64 = base64.b64encode(password_hash).decode()
    return password_hash_b64, salt_b64

# function to verify password by(sha256{secure hash algorithum 256-bit}) stored hash, salt and provided password
def verify_password(stored_hash, stored_salt, provided_password):
    salt = base64.b64decode(stored_salt.encode())
    password_hash = hashlib.pbkdf2_hmac("sha256", provided_password.encode(), salt, 100000)
    password_hash_b64 = base64.b64encode(password_hash).decode()
    return password_hash_b64 == stored_hash


