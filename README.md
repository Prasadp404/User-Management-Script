# User-Management-Script
Security vulnerability demonstration

# What This Script Does:

The User Management Script is a simple command-line application that:
•	Creates and manages user accounts
•	Stores user information in a SQLite database
•	Provides login functionality
•	Lists all registered users

# Note : For better understanding please check Readme.docx

The vulnerable version demonstrates 3 critical security issues commonly found in real-world applications.

All 3 Vulnerabilities Explained:

# Vulnerability 1: Hardcoded Credentials
Location: Lines 9-12 in vulnerable_user_manager.py

The Issue:
ADMIN_USERNAME = "Rio"
ADMIN_PASSWORD = "Rio404"   #Hardcoded password!
API_KEY = "01010111EZ000110101"   #Hardcoded API key!

Why It's Dangerous:
•	Credentials are visible to anyone who can see the source code
•	Cannot be changed without modifying code
•	If code is committed to Git/GitHub, secrets remain in history forever
•	Same credentials used across all environments (dev, test, production)
•	Developers, contractors, and anyone with repository access can see secrets

Real-World Example: In 2019, a developer accidentally pushed AWS credentials to GitHub. Bots found them within minutes and racked up $50,000 in cloud computing costs for cryptocurrency mining. – Source: Reddit.

Attack Scenario:
1. Attacker gains access to source code (GitHub leak, insider, etc.)
2. Finds hardcoded admin password: "admin123"
3. Uses credentials to log into admin account
4. Full system access granted

# Vulnerability 2: SQL Injection
Location: Lines 44-46 in vulnerable_user_manager.py

The Issue:
user input directly concatenated into SQL query
query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
cursor.execute(query)

Why It's Dangerous:
•	Attackers can manipulate SQL queries 
•	Bypass authentication without knowing passwords 
•	Read, modify, or delete any data in database 
•	Complete database compromise possible

OWASP Top 10: SQL injection has been in the top 3 most critical web vulnerabilities for over a decade

Attack Scenario: 
1 Bypasses authentication
2. Gains unauthorized access to user accounts
3. Can view, modify, or delete data
4. Complete system compromise

How SQL Injection Works:
Normal Query:
pythonusername = "admin"
password = "admin123"
query = "SELECT * FROM users WHERE username='admin' AND password='admin123'"

#Returns admin user if password is correct
Malicious Query:
pythonusername = "admin' OR '1'='1"
password = "anything"
query = "SELECT * FROM users WHERE username='admin' OR '1'='1' AND password='anything'"
#'1'='1' is always TRUE, so this returns the admin user regardless of password!

Attack Scenario:
Attacker's input:
  Username: admin' OR '1'='1' --
  Password: (anything)

Resulting SQL query:
  SELECT * FROM users WHERE username='admin' OR '1'='1' --' AND password='anything'
  
The '--' comments out the rest of the query, so it becomes:
  SELECT * FROM users WHERE username='admin' OR '1'='1'

Result: Login successful without knowing the password!
Other SQL Injection Attacks:
python# Dump all usernames and passwords
username = "' UNION SELECT username, password, email FROM users --"

#Delete all users
username = "'; DROP TABLE users; --"

#Read sensitive data from other tables
username = "' UNION SELECT credit_card, cvv, expiry FROM payments --"

# Vulnerability 3: Insecure File Handling
Location: Lines 89-115, 117-131 in vulnerable_user_manager.py

def export_user_data(filename):
    # No path validation - accepts any filename!
    with open(filename, 'w') as f:  # DANGEROUS!
        # Writes sensitive data to user-specified location
        f.write("USERNAME,PASSWORD,EMAIL,ROLE\n")
        for user in users:
            f.write(f"{user[0]},{user[1]},{user[2]},{user[3]}\n")

def import_user_data(filename):
    # No path validation - can read ANY file!
    with open(filename, 'r') as f:  # DANGEROUS!
        content = f.read()


•	Path Traversal: Attacker can read/write files anywhere on the system 
•	No Validation: Accepts any filename including ../../../etc/passwd 
•	Sensitive Data Exposure: Exports passwords in plain text files 
•	Arbitrary File Access: Can read system configuration files, private keys, etc. 
•	No Size Limits: Could load huge files causing denial of service

OWASP Top 10 (A01:2021): Path traversal is part of "Broken Access Control" category

# A safe/fixed version to Remove Hardcoded Credentials:

Bad Practice:
API_KEY = "01010111EZ000110101"  # Hardcoded

Good Practice:
import os
API_KEY = os.environ.get("API_KEY")  # From environment variable

if not API_KEY:
    raise RuntimeError("API_KEY environment variable not set")
 
# A safe/fixed version to Prevent SQL Injection

Bad Practice:

#String concatenation 
query = f"SELECT * FROM users WHERE username='{username}'"
cursor.execute(query)

Good Practice:
#Parameterized query 
query = "SELECT * FROM users WHERE username = ?"
cursor.execute(query, (username,))

# A safe/fixed version of Secure File Handling

Bad Practice:
#No validation 
def export_data(filename):
    with open(filename, 'w') as f:  # Accepts any path!
        f.write(sensitive_data)

Good Practice:
import os
import re
from pathlib import Path

#Define safe directories
SAFE_EXPORT_DIR = Path("./exports")
SAFE_EXPORT_DIR.mkdir(exist_ok=True)
def validate_filename(filename):
    """Validate filename to prevent path traversal"""
    
#Remove any directory separators
    filename = os.path.basename(filename)
    # Check for suspicious patterns
    if '..' in filename or '/' in filename or '\\' in filename:
        return None, "Invalid filename: contains path separators"
#Only allow safe characters
    if not re.match(r'^[a-zA-Z0-9_\-\.]+


# """Follow these steps to run the code:"""

# Running the Vulnerable Version:
#Run the vulnerable script
python vulnerable_user_manager.py

What it does:
1.	Creates SQLite database with sample users
2.	Displays all users with plain text passwords
3.	Demonstrates normal login
4.	Demonstrates SQL injection attack
5.	Shows hardcoded credentials

Expected Output:
•	 Login successful! (with valid credentials)
•	 Login successful! (with SQL injection payload - THIS IS BAD!)
•	 Passwords visible in plain text
•	 Hardcoded secrets exposed

# Running the Secure Version:
#Set environment variables
export ADMIN_PASSWORD="Enter Password"
export API_KEY="your_secure_api_key_here"

# Run the secure script
python secure_user_manager.py

What it does:
1.	Loads credentials from environment variables
2.	Creates database with hashed passwords
3.	Displays users WITHOUT passwords
4.	Demonstrates normal login
5.	Shows SQL injection protection (attack fails!)

Expected Output:
•	Login successful! (with valid credentials)
•	Login failed! (SQL injection blocked)
•	Passwords are hashed
•	No hardcoded secrets

# Testing the Vulnerabilities: 

Test 1: Hardcoded Credentials
#Open vulnerable_user_manager.py in text editor
#Lines 10-12 show hardcoded secrets clearly

#Anyone with source code access can see:
ADMIN_PASSWORD = "admin123"
API_KEY = "01010111EZ000110101"

Test 2: Plain Text Passwords
#Run vulnerable version
python vulnerable_user_manager.py

Output shows passwords in plain text:
Password: admin123
Password: password123
Password: sarah2024

Test 3: SQL Injection
#The script automatically demonstrates this:
python vulnerable_user_manager.py
#Look for the section:
#"Demonstrating SQL Injection Vulnerability"
#It successfully logs in using: admin' OR '1'='1


# Assignment Focus: 
Demonstrate understanding of security vulnerabilities and secure coding practices.

# Reference: 
OWASP, CVE

# License
Educational use only. Created for Cybersecurity Engineer job interview assignment.
