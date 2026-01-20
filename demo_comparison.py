# demo_comparison.py
# Side-by-side demonstration of vulnerable vs secure code

def demonstrate_vulnerability_1():
    """Demonstrate Hardcoded Credentials"""
    print("=" * 70)
    print("VULNERABILITY 1: HARDCODED CREDENTIALS")
    print("=" * 70)
    print()
    
    print(" VULNERABLE CODE:")
    print("-" * 70)
    print("""
# Hardcoded in source code
ADMIN_PASSWORD = "admin123"
API_KEY = "sk_live_1234567890abcdef"
    """)
    print("Problem: Anyone with source code access can see these secrets!")
    print()
    
    print(" SECURE CODE:")
    print("-" * 70)
    print("""
import os

# Load from environment variables
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD")
API_KEY = os.environ.get("API_KEY")

if not ADMIN_PASSWORD or not API_KEY:
    raise RuntimeError("Environment variables not set")
    """)
    print("Solution: Secrets stored outside code, cannot be accidentally committed")
    print()

def demonstrate_vulnerability_2():
    """Demonstrate SQL Injection"""
    print("=" * 70)
    print("VULNERABILITY 2: SQL INJECTION")
    print("=" * 70)
    print()
    
    print("VULNERABLE CODE:")
    print("-" * 70)
    print("""
# String concatenation - DANGEROUS!
username = input("Username: ")  # User enters: admin' OR '1'='1
password = input("Password: ")

query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
cursor.execute(query)

# Actual query executed:
# SELECT * FROM users WHERE username='admin' OR '1'='1' AND password='...'
# '1'='1' is always TRUE → Authentication bypassed!
    """)
    print("Problem: Attacker can manipulate SQL query structure")
    print()
    
    print("SECURE CODE:")
    print("-" * 70)
    print("""
# Parameterized query - SAFE!
username = input("Username: ")  # User enters: admin' OR '1'='1
password = input("Password: ")

query = "SELECT * FROM users WHERE username = ? AND password = ?"
cursor.execute(query, (username, password))

# Database treats entire input as data, not code
# Looks for user literally named "admin' OR '1'='1"
# Attack fails!
    """)
    print("Solution: User input treated as data only, cannot modify query structure")
    print()

def demonstrate_vulnerability_3():
    """Demonstrate Insecure File Handling"""
    print("=" * 70)
    print("VULNERABILITY 3: INSECURE FILE HANDLING")
    print("=" * 70)
    print()
    
    print(" VULNERABLE CODE:")
    print("-" * 70)
    print("""
# No path validation - DANGEROUS!
def export_data(filename):
    with open(filename, 'w') as f:  # Accepts ANY path!
        f.write(sensitive_data)

# User can provide malicious paths:
export_data("../../../etc/passwd")
export_data("../../tmp/stolen_data.csv")
export_data("C:\\\\Windows\\\\System32\\\\config\\\\SAM")
    """)
    print("Problem: Attacker can read/write files anywhere on the system")
    print()
    
    print("SECURE CODE:")
    print("-" * 70)
    print("""
import os
from pathlib import Path

# Define safe directory
SAFE_DIR = Path("./exports")

def validate_filename(filename):
    # Remove directory components
    filename = os.path.basename(filename)
    
    # Check for path traversal
    if '..' in filename or '/' in filename:
        raise ValueError("Invalid filename")
    
    return filename

def export_data(filename):
    # Validate filename
    safe_filename = validate_filename(filename)
    
    # Build path within safe directory
    safe_path = SAFE_DIR / safe_filename
    
    # Verify path is within safe directory
    if not str(safe_path.resolve()).startswith(str(SAFE_DIR.resolve())):
        raise ValueError("Path traversal blocked")
    
    with open(safe_path, 'w') as f:
        f.write(non_sensitive_data)
    """)
    print("Solution: Validate paths, restrict to safe directories, check file extensions")
    print()

def show_attack_demo():
    """Show practical SQL injection attack"""
    print("=" * 70)
    print("SQL INJECTION ATTACK DEMONSTRATION")
    print("=" * 70)
    print()
    
    print("Normal Login:")
    print("  Username: admin")
    print("  Password: admin123")
    print("  Query: SELECT * FROM users WHERE username='admin' AND password='admin123'")
    print("  Result: Returns admin user if password is correct")
    print()
    
    print("SQL Injection Attack:")
    print("  Username: admin' OR '1'='1")
    print("  Password: anything")
    print("  Query: SELECT * FROM users WHERE username='admin' OR '1'='1' AND password='anything'")
    print("  Result: Returns admin user WITHOUT correct password!")
    print()
    
    print("Why it works:")
    print("  - The OR condition makes the WHERE clause always TRUE")
    print("  - '1'='1' is always TRUE")
    print("  - Password check is bypassed")
    print()
    
    print("Other possible attacks:")
    print("  ' OR '1'='1' --          (Comment out rest of query)")
    print("  '; DROP TABLE users; --  (Delete entire table)")
    print("  ' UNION SELECT * FROM passwords --  (Access other tables)")
    print()

def main():
    print("\n")
    print("SECURITY VULNERABILITIES DEMONSTRATION")
    print()
    
    demonstrate_vulnerability_1()
    input("Press Enter to continue...")
    print()
    

    demonstrate_vulnerability_2()
    input("Press Enter to continue...")
    print()
    
    demonstrate_vulnerability_3()
    input("Press Enter to continue...")
    print()
    
    show_attack_demo()
    
    print("=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print()
    print("3 Critical Vulnerabilities Demonstrated:")
    print()
    print("1.  Hardcoded Credentials")
    print("  Fix: Use environment variables")
    print()
    print("2.  SQL Injection")
    print("    Fix: Use parameterized queries")
    print()
    print("3.  Insecure File Handling")
    print("    Fix: Validate paths and restrict to safe directories")
    print()
    print("=" * 70)
    print()
    print("For full code examples, see:")
    print("  - vulnerable_user_manager.py (with vulnerabilities)")
    print("  - secure_user_manager.py (all vulnerabilities fixed)")
    print()

if __name__ == "__main__":
    main()