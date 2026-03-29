import sqlite3
from datetime import datetime
import bcrypt

# Database file name
DB_NAME = 'chat_history.db'

def init_db():
    """
    Sets up the SQLite database and tables. 
    Creates a default admin user on the first run if one doesn't exist.
    """
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # Main history table. We're keeping it simple without user_ids 
    # to decouple logs from specific accounts and prevent constraint crashes.
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            original_input TEXT,
            secured_input TEXT,
            ai_response TEXT,
            timestamp TEXT
        )
    ''')

    # Table for login credentials
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    ''')

    # Create a default admin account if the users table is empty
    cursor.execute('SELECT * FROM users WHERE username="admin"')
    if not cursor.fetchone():
        # Hash the default password using bcrypt before saving
        hashed = bcrypt.hashpw("admin123".encode('utf-8'), bcrypt.gensalt())
        cursor.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)', ("admin", hashed.decode('utf-8')))
        print("Default Admin created: admin / admin123")

    conn.commit()
    conn.close()

def verify_user(username, password):
    """
    Checks if the provided username and password match our stored bcrypt hash.
    
    Args:
        username (str): The typed username.
        password (str): The plain text password.
        
    Returns:
        bool: True if the password matches, False otherwise.
    """
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('SELECT password_hash FROM users WHERE username=?', (username,))
    row = cursor.fetchone()
    conn.close()
    
    if row:
        hashed_password = row[0].encode('utf-8')
        # Compare the plain password against the stored hash
        if bcrypt.checkpw(password.encode('utf-8'), hashed_password):
            return True
    return False

def save_to_history(original, secured, response):
    """
    Saves a single chat interaction to the history table.
    
    Args:
        original (str): Raw user input.
        secured (str): Masked input sent to the LLM.
        response (str): The AI's reply.
    """
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # Format timestamp for the UI (e.g., 24/03/2026 01:04 AM)
    now = datetime.now().strftime("%d/%m/%Y %I:%M %p") 
    
    cursor.execute('''
        INSERT INTO history (original_input, secured_input, ai_response, timestamp)
        VALUES (?, ?, ?, ?)
    ''', (original, secured, response, now))
    
    conn.commit()
    conn.close()

def fetch_history():
    """
    Gets all chat logs from the database, newest first.
    
    Returns:
        list: A list of tuples containing the rows.
    """
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM history ORDER BY id DESC')
    rows = cursor.fetchall()
    conn.close()
    return rows

def clear_history():
    """
    Deletes all rows from the history table. Useful for UI resets.
    """
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM history")
    conn.commit()
    conn.close()
    print("Database Cleared!")