from auth import hash_password, verify_password

def test_hash_and_verify_password():
    password = "my_secure_password"
    hashed, salt = hash_password(password)
    assert verify_password(hashed, salt, password) == True
    assert verify_password(hashed, salt, "wrong_password") == False
