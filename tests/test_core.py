import pytest
from core import hash_passkey, encrypt_data, decrypt_data

def test_hash_passkey():
    passkey = "secure123"
    hashed = hash_passkey(passkey)

    assert isinstance(hashed, str)
    assert len(hashed) == 64  # SHA-256 produces 64 hex characters
    assert hashed != passkey

def test_encrypt_data_returns_encrypted_and_hash():
    text = "secret message"
    passkey = "mypassword"
    encrypted_text, hashed_passkey = encrypt_data(text, passkey)

    assert isinstance(encrypted_text, str)
    assert isinstance(hashed_passkey, str)
    assert encrypted_text != text

def test_decrypt_data_with_correct_passkey():
    text = "sensitive data"
    passkey = "correctkey"
    encrypted_text, hashed_passkey = encrypt_data(text, passkey)

    decrypted = decrypt_data(encrypted_text, hashed_passkey, passkey)
    assert decrypted == text

def test_decrypt_data_with_wrong_passkey_returns_none():
    text = "confidential"
    correct_passkey = "right"
    wrong_passkey = "wrong"

    encrypted_text, hashed_passkey = encrypt_data(text, correct_passkey)
    decrypted = decrypt_data(encrypted_text, hashed_passkey, wrong_passkey)

    assert decrypted is None
