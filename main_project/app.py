# imports
import streamlit as st
from auth import hash_password, verify_password
from db import create_db, add_user, get_user_by_username
from session_state import get_session_state, login_user, logout_user, increment_failed_attempts, reset_failed_attempts
from core import encrypt_data, decrypt_data

# Initialize database and session state
create_db()
state = get_session_state()

# Sidebar - Navigation
menu = st.sidebar.selectbox("Menu", ["Home", "Register", "Login", "Encrypt", "Decrypt", "Logout"])

# -------------------------------
# Home
if menu == "Home":
    st.title("🔐 Secure Data Encryption System")
    st.write("This app securely handles user registration, login, and allows encrypted storage of sensitive data using hashing and encryption techniques.")

# -------------------------------
# Register
elif menu == "Register":
    st.header("Create an Account")

    username = st.text_input("Username")
    email = st.text_input("Email")
    password = st.text_input("Password", type="password")

    if st.button("Register"):
        if username and password and email:
            if get_user_by_username(username):
                st.warning("🚫 Username already exists.")
            else:
                hashed_pw, salt = hash_password(password)
                add_user(username, hashed_pw, salt, email)
                st.success("✅ Registered Successfully! You can now log in.")
        else:
            st.warning("⚠️ Please fill all fields.")

# -------------------------------
# Login
elif menu == "Login":
    st.header("Login")

    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        user = get_user_by_username(username)
        if user:
            stored_hash, stored_salt = user[2], user[3]
            if verify_password(stored_hash, stored_salt, password):
                login_user(username)
                st.success(f"✅ Welcome, {username}!")
            else:
                increment_failed_attempts()
                st.error("❌ Incorrect password.")
        else:
            st.error("❌ User not found.")

# -------------------------------
# Encrypt
elif menu == "Encrypt":
    if state.logged_in:
        st.header("🔒 Encrypt Your Data")
        text = st.text_area("Enter text to encrypt")
        passkey = st.text_input("Enter passkey", type="password")

        if st.button("Encrypt"):
            if text and passkey:
                encrypted_text, hashed_passkey = encrypt_data(text, passkey)
                st.success("✅ Data Encrypted")
                st.code(encrypted_text, language="text")
                st.info("⚠️ Please remember your passkey for decryption.")
                st.session_state.last_encrypted = encrypted_text
                st.session_state.last_hashed_passkey = hashed_passkey
            else:
                st.warning("⚠️ Please provide both text and passkey.")
    else:
        st.warning("🚫 Please login to access this section.")

# -------------------------------
# Decrypt
elif menu == "Decrypt":
    if state.logged_in:
        st.header("🔓 Decrypt Your Data")
        encrypted_text = st.text_area("Paste encrypted text")
        passkey = st.text_input("Enter your passkey", type="password")

        if st.button("Decrypt"):
            if encrypted_text and passkey:
                hashed_passkey = st.session_state.get("last_hashed_passkey")
                if not hashed_passkey:
                    st.error("⚠️ No encryption context found. Try encrypting again or reload app.")
                else:
                    result = decrypt_data(encrypted_text, hashed_passkey, passkey)
                    if result:
                        st.success("✅ Decryption Successful")
                        st.code(result, language="text")
                    else:
                        st.error("❌ Incorrect passkey or corrupted data.")
            else:
                st.warning("⚠️ Please fill both fields.")
    else:
        st.warning("🚫 Please login to access this section.")

# -------------------------------
# Logout
elif menu == "Logout":
    logout_user()
    st.success("👋 You have been logged out.")
