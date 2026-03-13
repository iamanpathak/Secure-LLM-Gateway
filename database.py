import sqlite3
from datetime import datetime
import bcrypt

# Maintain the same database name used in main.py
DB_NAME = 'chat_history.db'

def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # 1. Core history table (Kept simple without user_id to prevent crashes)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            original_input TEXT,
            secured_input TEXT,
            ai_response TEXT,
            timestamp TEXT
        )
    ''')

    # 2. Users table for Authentication (Login system)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    ''')

    # 3. Create a default Admin account (if it doesn't already exist)
    cursor.execute('SELECT * FROM users WHERE username="admin"')
    if not cursor.fetchone():
        # Encrypting the default password 'admin123'
        hashed = bcrypt.hashpw("admin123".encode('utf-8'), bcrypt.gensalt())
        cursor.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)', ("admin", hashed.decode('utf-8')))
        print("Default Admin created: admin / admin123")

    conn.commit()
    conn.close()

def verify_user(username, password):
    """Verifies if the provided username and password are correct"""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('SELECT password_hash FROM users WHERE username=?', (username,))
    row = cursor.fetchone()
    conn.close()
    
    if row:
        hashed_password = row[0].encode('utf-8')
        # Using Bcrypt to check if the typed password matches the stored hash
        if bcrypt.checkpw(password.encode('utf-8'), hashed_password):
            return True
    return False

def save_to_history(original, secured, response):
    """Saves chat to database with 3 arguments (matched with main.py)"""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # Custom timestamp format: DD/MM/YYYY HH:MM AM/PM
    now = datetime.now().strftime("%d/%m/%Y %I:%M %p") 
    
    cursor.execute('''
        INSERT INTO history (original_input, secured_input, ai_response, timestamp)
        VALUES (?, ?, ?, ?)
    ''', (original, secured, response, now))
    
    conn.commit()
    conn.close()

def fetch_history():
    """Fetches all history logs"""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    # Fetching id, original_input, secured_input, ai_response, and timestamp
    cursor.execute('SELECT * FROM history ORDER BY id DESC')
    rows = cursor.fetchall()
    conn.close()
    return rows

def clear_history():
    """Wipes all data for a fresh start"""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM history")
    conn.commit()
    conn.close()
    print("Database Cleared!")