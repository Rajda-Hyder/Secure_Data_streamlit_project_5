import os
import sqlite3
from db import create_db, add_user, get_user_by_username

def test_create_and_add_user():
    test_db = "test_user_data.db"
    if os.path.exists(test_db):
        os.remove(test_db)

    # Create test database
    conn = sqlite3.connect(test_db)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()

    # Add a test user
    username = "testuser"
    password_hash = "hashed"
    salt = "salt"
    email = "test@example.com"
    cursor.execute('''
        INSERT INTO users (username, password_hash, salt, email)
        VALUES (?, ?, ?, ?)
    ''', (username, password_hash, salt, email))
    conn.commit()

    # Fetch user
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()

    assert user is not None
    assert user[1] == "testuser"
