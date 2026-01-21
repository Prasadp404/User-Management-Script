# vulnerable_user_manager.py
# VULNERABLE VERSION - DO NOT USE IN PRODUCTION!
# This script contains intentional security vulnerabilities for educational purposesimport sqlite3

import sqlite3
import os

# VULNERABILITY 1: Hardcoded Credentials
DB_NAME = "users.db"
ADMIN_USERNAME = "Rio"
ADMIN_PASSWORD = "Rio404"  
API_KEY = "01010111EZ000110101"  

def init_database():
    """Initialize the database with a sample admin user"""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # Create users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT,
            role TEXT DEFAULT 'user'
        )
    ''')
    
    # Insert admin user
    cursor.execute('''
                   
        INSERT OR IGNORE INTO users (username, password, email, role) 
        VALUES (?, ?, ?, ?)
    ''', (ADMIN_USERNAME, ADMIN_PASSWORD, "CISO@vuln.com", "CISO"))
    
    conn.commit()
    conn.close()
    print("[+] Database initialized")

def login(username, password):
    """
    VULNERABILITY 2: SQL Injection
    User input is directly concatenated into SQL query
    """
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # SQL Injection vulnerability - direct string concatenation
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    
    print(f"[DEBUG] Executing query: {query}")
    
    try:
        cursor.execute(query)
        user = cursor.fetchone()
        conn.close()
        
        if user:
            print(f"\n Login successful!")
            print(f"  User ID: {user[0]}")
            print(f"  Username: {user[1]}")
            print(f"  Email: {user[3]}")
            print(f"  Role: {user[4]}")
            return True
        else:
            print("\n Login failed: Invalid credentials")
            return False
    except sqlite3.Error as e:
        print(f"\n Database error: {e}")
        conn.close()
        return False

def create_user(username, password, email):
    """Create a new user"""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    try:
        cursor.execute('''
            INSERT INTO users (username, password, email) 
            VALUES (?, ?, ?)
        ''', (username, password, email))
        
        conn.commit()
        print(f"\nUser '{username}' created successfully!")
        conn.close()
        return True
    except sqlite3.IntegrityError:
        print(f"\n Error: Username '{username}' already exists")
        conn.close()
        return False

def export_user_data(filename):
    """
    VULNERABILITY 3: Insecure File Handling
    No validation on filename, allows directory traversal
    Writes sensitive data to user-specified location
    """
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # Get all users
    cursor.execute("SELECT username, password, email, role FROM users")
    users = cursor.fetchall()
    conn.close()
    
    # VULNERABILITY: No path validation - allows directory traversal
    # VULNERABILITY: No permission checks on file writing
    # VULNERABILITY: Exports sensitive data (passwords) to plain text file
    try:
        with open(filename, 'w') as f:
            f.write("USERNAME,PASSWORD,EMAIL,ROLE\n")
            for user in users:
                f.write(f"{user[0]},{user[1]},{user[2]},{user[3]}\n")
        
        print(f"\n User data exported to: {filename}")
        print(f"  File contains plain text passwords!")
        return True
    except Exception as e:
        print(f"\nError exporting data: {e}")
        return False

def import_user_data(filename):
    """
    VULNERABILITY 3: Insecure File Handling
    No validation on file path, allows reading arbitrary files
    No validation on file contents
    """
    # VULNERABILITY: No path validation - allows directory traversal
    # VULNERABILITY: No file type checking
    # VULNERABILITY: No size limit checking
    try:
        with open(filename, 'r') as f:
            content = f.read()
            print(f"\n File content read successfully:")
            print(content)
            return content
    except Exception as e:
        print(f"\nError reading file: {e}")
        return None

def main():
    """
    Main function to demonstrate the vulnerable Employee management system
    """
    print("-"*70)
    print("VULNERABLE Employee MANAGEMENT SYSTEM")
    print("-"*70)
    
    # Initialize database
    init_database()
    
    # Create some sample users
    print("\n--- Creating Sample Users ---")
    create_user("Eric", "Eric123", "Eric@vuln.com")
    create_user("Veer", "veer2024", "Veer@vuln.com")
    
    # Demonstrate normal login
    print("\n--- Testing Normal Login ---")
    login("Rio", "Rio404")
    
    # VULNERABILITY 2: Demonstrate SQL injection
    print("\n" + "="*70)
    print("DEMONSTRATING VULNERABILITY 2: SQL INJECTION")
    print("="*70)
    print("\nTrying SQL injection payload: admin' --")
    print("Explanation: The '--' comments out the password check")
    login("admin' --", "anything")
    
    print("\nTrying another SQL injection: ' OR '1'='1' --")
    print("Explanation: Always true condition with comment")
    login("' OR '1'='1' --", "anything")
    
    # VULNERABILITY 3: Demonstrate insecure file handling
    print("\n" + "="*70)
    print("DEMONSTRATING VULNERABILITY 3: INSECURE FILE HANDLING")
    print("="*70)
    
    # Export to arbitrary location (path traversal)
    print("\n1. Exporting sensitive data to file...")
    export_user_data("user_data.csv")
    
    print("\n2. Attempting path traversal export...")
    export_user_data("C:\\Users\\hp\\Dropbox\\py\\stolen_data.csv")
    print("   WARNING: File written outside application directory!")
    
    print("\n3. Reading arbitrary file...")
    import_user_data("user_data.csv")
    
    print("\n4. Attempting to read sensitive system file...")
    print("C:\\Windows\\System32\\drivers\\etc\\hosts")
    # This will fail on most systems due to permissions, but demonstrates the vulnerability
    import_user_data("C:\\Windows\\System32\\drivers\\etc\\hosts")
    
    # VULNERABILITY 1: Show hardcoded credentials
    print("\n" + "-"*70)
    print("DEMONSTRATING VULNERABILITY 1: HARDCODED CREDENTIALS")
    print("-"*70)
    print(f"\nHardcoded admin password: {ADMIN_PASSWORD}")
    print(f"Hardcoded API key: {API_KEY}")
    print("\nWARNING: These secrets are visible to anyone who can see the source code!")
    

if __name__ == "__main__":
    main()
