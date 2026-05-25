import sqlite3
import os
import hashlib
import requests
import time
import pyperclip
import random
import string
import re
import getpass
import argparse

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

DB_NAME = "vault.db"

# ================= DATABASE =================
def init_db():
    """Initialize database and create tables if not exist."""
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()

    c.execute('''
        CREATE TABLE IF NOT EXISTS master (
            id INTEGER PRIMARY KEY,
            salt BLOB
        )
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS vault (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            site TEXT,
            username TEXT,
            encrypted_password BLOB,
            iv BLOB
        )
    ''')

    conn.commit()
    conn.close()

# ================= KEY DERIVATION =================
def derive_key(password, salt):
    """Derive encryption key using PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return kdf.derive(password.encode())

def get_salt():
    """Retrieve or generate salt."""
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()

    c.execute("SELECT salt FROM master WHERE id=1")
    row = c.fetchone()

    if row:
        return row[0]

    salt = os.urandom(16)
    c.execute("INSERT INTO master (id, salt) VALUES (1, ?)", (salt,))
    conn.commit()
    conn.close()
    return salt

# ================= ENCRYPTION =================
def encrypt_password(key, password):
    """Encrypt password using AES-256-GCM."""
    aes = AESGCM(key)
    iv = os.urandom(12)
    encrypted = aes.encrypt(iv, password.encode(), None)
    return encrypted, iv

def decrypt_password(key, encrypted, iv):
    """Decrypt password."""
    aes = AESGCM(key)
    return aes.decrypt(iv, encrypted, None).decode()

# ================= PASSWORD UTILITIES =================
def generate_password(length=12):
    """Generate strong random password."""
    chars = string.ascii_letters + string.digits + "!@#$%^&*()"
    return ''.join(random.choice(chars) for _ in range(length))

def is_strong(password):
    """Check password strength."""
    return (
        len(password) >= 8 and
        re.search(r"[A-Z]", password) and
        re.search(r"[a-z]", password) and
        re.search(r"[0-9]", password) and
        re.search(r"[!@#$%^&*()]", password)
    )

# ================= BREACH CHECK =================
def check_pwned(password):
    """Check password using HaveIBeenPwned API (k-anonymity)."""
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix = sha1[:5]
    suffix = sha1[5:]

    res = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}")

    for line in res.text.splitlines():
        h, count = line.split(":")
        if h == suffix:
            print(f"⚠ Password found {count} times in breaches!")
            return True
    return False

# ================= CRUD =================
def add_entry(key):
    site = input("Site: ")
    username = input("Username: ")

    choice = input("1. Enter password\n2. Generate password\nChoose: ")

    if choice == "2":
        password = generate_password()
        print("Generated:", password)
    else:
        password = getpass.getpass("Password: ")

        if not is_strong(password):
            print("❌ Weak password")
            return

    if check_pwned(password):
        print("❌ Password compromised")
        return

    encrypted, iv = encrypt_password(key, password)

    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("INSERT INTO vault (site, username, encrypted_password, iv) VALUES (?, ?, ?, ?)",
              (site, username, encrypted, iv))
    conn.commit()
    conn.close()

    print("✔ Added")

def view_entries(key):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()

    c.execute("SELECT * FROM vault")
    for row in c.fetchall():
        print(f"[{row[0]}] {row[1]} | {row[2]} | {decrypt_password(key, row[3], row[4])}")

    conn.close()

def delete_entry():
    id = input("Enter ID: ")
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("DELETE FROM vault WHERE id=?", (id,))
    conn.commit()
    conn.close()
    print("✔ Deleted")

def update_entry(key):
    id = input("Enter ID: ")
    new_password = getpass.getpass("New password: ")

    encrypted, iv = encrypt_password(key, new_password)

    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("UPDATE vault SET encrypted_password=?, iv=? WHERE id=?",
              (encrypted, iv, id))
    conn.commit()
    conn.close()

    print("✔ Updated")

def search_entries(key):
    keyword = input("Search: ")
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()

    q = f"%{keyword}%"
    c.execute("SELECT * FROM vault WHERE site LIKE ? OR username LIKE ?", (q, q))

    rows = c.fetchall()
    if not rows:
        print("❌ No results")
    else:
        for r in rows:
            print(f"[{r[0]}] {r[1]} | {r[2]} | {decrypt_password(key, r[3], r[4])}")

    conn.close()

def copy_clipboard(key):
    id = input("Enter ID: ")
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()

    c.execute("SELECT encrypted_password, iv FROM vault WHERE id=?", (id,))
    row = c.fetchone()

    if row:
        password = decrypt_password(key, row[0], row[1])
        pyperclip.copy(password)
        print("✔ Copied (clears in 30 sec)")
        time.sleep(30)
        pyperclip.copy("")
        print("✔ Cleared")

# ================= ARGPARSE =================
# ================= ARGPARSE =================
def handle_args(key):

    parser = argparse.ArgumentParser(
        description="[LOCK] Password Manager CLI",

        epilog="""
Examples:

python cli.py add --site Facebook --username habiba --password Pass@123

python cli.py view

python cli.py search --keyword gmail

python cli.py generate --length 16
""",

        formatter_class=argparse.RawTextHelpFormatter
    )

    subparsers = parser.add_subparsers(dest="command")

    # ================= ADD =================
    add_parser = subparsers.add_parser(
        "add",
        help="Add new password entry"
    )

    add_parser.add_argument(
        "--site",
        required=True,
        help="Website name"
    )

    add_parser.add_argument(
        "--username",
        required=True,
        help="Account username"
    )

    add_parser.add_argument(
        "--password",
        required=True,
        help="Account password"
    )

    # ================= VIEW =================
    subparsers.add_parser(
        "view",
        help="View all saved passwords"
    )

    # ================= SEARCH =================
    search_parser = subparsers.add_parser(
        "search",
        help="Search entries"
    )

    search_parser.add_argument(
        "--keyword",
        required=True,
        help="Search keyword"
    )

    # ================= GENERATE =================
    gen_parser = subparsers.add_parser(
        "generate",
        help="Generate strong password"
    )

    gen_parser.add_argument(
        "--length",
        type=int,
        default=12,
        help="Password length"
    )

    # IMPORTANT
    args = parser.parse_args()

    # ================= COMMANDS =================

    if args.command == "add":

        if check_pwned(args.password):
            print("❌ Password compromised!")
            return

        if not is_strong(args.password):
            print("❌ Weak password")
            return

        encrypted, iv = encrypt_password(key, args.password)

        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()

        c.execute(
            "INSERT INTO vault (site, username, encrypted_password, iv) VALUES (?, ?, ?, ?)",
            (args.site, args.username, encrypted, iv)
        )

        conn.commit()
        conn.close()

        print("✔ Added Successfully")

    elif args.command == "view":

        view_entries(key)

    elif args.command == "search":

        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()

        q = f"%{args.keyword}%"

        c.execute(
            "SELECT * FROM vault WHERE site LIKE ? OR username LIKE ?",
            (q, q)
        )

        rows = c.fetchall()

        if not rows:
            print("❌ No results")

        else:
            for r in rows:
                print(
                    f"[{r[0]}] {r[1]} | {r[2]} | "
                    f"{decrypt_password(key, r[3], r[4])}"
                )

        conn.close()

    elif args.command == "generate":

        password = generate_password(args.length)

        print("🔐 Generated Password:", password)


# ================= MAIN =================
def main():

    init_db()
    salt = get_salt()

    # لو المستخدم كتب help
    if "-h" in os.sys.argv or "--help" in os.sys.argv:
        handle_args(None)
        return

    # باقي الأوامر تحتاج master password
    if len(os.sys.argv) > 1:

        master = getpass.getpass("Enter master password: ")

        key = derive_key(master, salt)

        handle_args(key)


if __name__ == "__main__":
    main()