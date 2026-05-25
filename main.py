import customtkinter as ctk
from tkinter import messagebox
import sqlite3
import os
import random
import string
import re
import pyperclip

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ================= SETTINGS =================
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

DB_NAME = "vault.db"

# ================= DATABASE =================
def init_db():

    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()

    c.execute("""
        CREATE TABLE IF NOT EXISTS master (
            id INTEGER PRIMARY KEY,
            salt BLOB
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS vault (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            site TEXT,
            username TEXT,
            encrypted_password BLOB,
            iv BLOB
        )
    """)

    conn.commit()
    conn.close()

# ================= ENCRYPTION =================
def derive_key(password, salt):

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )

    return kdf.derive(password.encode())


def get_salt():

    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()

    c.execute("SELECT salt FROM master WHERE id=1")

    row = c.fetchone()

    if row:
        conn.close()
        return row[0]

    salt = os.urandom(16)

    c.execute(
        "INSERT INTO master (id, salt) VALUES (1, ?)",
        (salt,)
    )

    conn.commit()
    conn.close()

    return salt


def encrypt_password(key, password):

    aes = AESGCM(key)

    iv = os.urandom(12)

    encrypted = aes.encrypt(
        iv,
        password.encode(),
        None
    )

    return encrypted, iv


def decrypt_password(key, encrypted, iv):

    aes = AESGCM(key)

    return aes.decrypt(
        iv,
        encrypted,
        None
    ).decode()

# ================= PASSWORD =================
def generate_password(length=12):

    chars = (
        string.ascii_letters +
        string.digits +
        "!@#$%^&*()"
    )

    return ''.join(
        random.choice(chars)
        for _ in range(length)
    )


def is_strong(password):

    return (
        len(password) >= 8 and
        re.search(r"[A-Z]", password) and
        re.search(r"[a-z]", password) and
        re.search(r"[0-9]", password) and
        re.search(r"[!@#$%^&*()]", password)
    )

# ================= APP =================
class PasswordManagerGUI(ctk.CTk):

    def __init__(self):

        super().__init__()

        self.title("Password Manager")
        self.geometry("1200x700")

        self.configure(fg_color="#1E1E1E")

        init_db()

        salt = get_salt()

        self.master_password = "1234"

        self.key = derive_key(
            self.master_password,
            salt
        )

        self.create_sidebar()
        self.create_topbar()
        self.create_main_area()

        self.load_passwords()

    # ================= SIDEBAR =================
    def create_sidebar(self):

        self.sidebar = ctk.CTkFrame(
            self,
            width=220,
            corner_radius=0,
            fg_color="#111111"
        )

        self.sidebar.pack(
            side="left",
            fill="y"
        )

        title = ctk.CTkLabel(
            self.sidebar,
            text="Password Manager",
            font=("Arial", 28, "bold")
        )

        title.pack(pady=40)

        btn1 = ctk.CTkButton(
            self.sidebar,
            text="Passwords",
            height=50,
            corner_radius=15,
            fg_color="#4C8DFF",
            command=self.load_passwords
        )

        btn1.pack(
            fill="x",
            padx=20,
            pady=10
        )

        btn2 = ctk.CTkButton(
            self.sidebar,
            text="Checkup",
            height=50,
            corner_radius=15,
            fg_color="#2B2B2B",
            command=self.show_checkup
        )

        btn2.pack(
            fill="x",
            padx=20,
            pady=10
        )

        btn3 = ctk.CTkButton(
            self.sidebar,
            text="Settings",
            height=50,
            corner_radius=15,
            fg_color="#2B2B2B",
            command=self.show_settings
        )

        btn3.pack(
            fill="x",
            padx=20,
            pady=10
        )

    # ================= TOPBAR =================
    def create_topbar(self):

        self.topbar = ctk.CTkFrame(
            self,
            height=80,
            fg_color="#1E1E1E"
        )

        self.topbar.pack(fill="x")

        self.search_entry = ctk.CTkEntry(
            self.topbar,
            width=600,
            height=45,
            corner_radius=25,
            placeholder_text="Search passwords"
        )

        self.search_entry.pack(
            side="left",
            padx=30,
            pady=20
        )

        self.search_entry.bind(
            "<KeyRelease>",
            self.search_passwords
        )

        self.add_btn = ctk.CTkButton(
            self.topbar,
            text="Add",
            width=100,
            height=40,
            corner_radius=20,
            command=self.add_popup
        )

        self.add_btn.pack(
            side="right",
            padx=30
        )

    # ================= MAIN AREA =================
    def create_main_area(self):

        self.main_frame = ctk.CTkScrollableFrame(
            self,
            fg_color="#1E1E1E"
        )

        self.main_frame.pack(
            fill="both",
            expand=True,
            padx=20,
            pady=10
        )

    # ================= LOAD =================
    def load_passwords(self):

        for widget in self.main_frame.winfo_children():
            widget.destroy()

        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()

        c.execute("SELECT * FROM vault")

        rows = c.fetchall()

        conn.close()

        for row in rows:
            self.create_password_card(row)

    # ================= PASSWORD CARD =================
    def create_password_card(self, row):

        password = decrypt_password(
            self.key,
            row[3],
            row[4]
        )

        card = ctk.CTkFrame(
            self.main_frame,
            height=70,
            corner_radius=15,
            fg_color="#2B2B2B"
        )

        card.pack(
            fill="x",
            pady=8,
            padx=10
        )

        site_label = ctk.CTkLabel(
            card,
            text=row[1],
            font=("Arial", 18, "bold")
        )

        site_label.pack(
            side="left",
            padx=20
        )

        user_label = ctk.CTkLabel(
            card,
            text=row[2],
            font=("Arial", 15)
        )

        user_label.pack(
            side="left",
            padx=30
        )

        pass_label = ctk.CTkLabel(
            card,
            text="•" * len(password),
            font=("Arial", 16)
        )

        pass_label.pack(
            side="left",
            padx=30
        )

        delete_btn = ctk.CTkButton(
            card,
            text="Delete",
            width=70,
            fg_color="#E53935",
            command=lambda:
            self.delete_password(row[0])
        )

        delete_btn.pack(
            side="right",
            padx=10
        )

        copy_btn = ctk.CTkButton(
            card,
            text="Copy",
            width=70,
            command=lambda:
            self.copy_password(password)
        )

        copy_btn.pack(
            side="right",
            padx=10
        )

        show_btn = ctk.CTkButton(
            card,
            text="Show",
            width=70,
            command=lambda:
            messagebox.showinfo(
                "Password",
                password
            )
        )

        show_btn.pack(
            side="right",
            padx=10
        )

    # ================= ADD POPUP =================
    def add_popup(self):

        popup = ctk.CTkToplevel(self)

        popup.geometry("450x450")
        popup.title("Add Password")

        popup.grab_set()

        title = ctk.CTkLabel(
            popup,
            text="Add New Password",
            font=("Arial", 24, "bold")
        )

        title.pack(pady=20)

        site_entry = ctk.CTkEntry(
            popup,
            width=350,
            height=45,
            placeholder_text="Website"
        )

        site_entry.pack(pady=10)

        username_entry = ctk.CTkEntry(
            popup,
            width=350,
            height=45,
            placeholder_text="Username"
        )

        username_entry.pack(pady=10)

        password_entry = ctk.CTkEntry(
            popup,
            width=350,
            height=45,
            placeholder_text="Password"
        )

        password_entry.pack(pady=10)

        def generate():

            password_entry.delete(0, "end")

            password_entry.insert(
                0,
                generate_password()
            )

        generate_btn = ctk.CTkButton(
            popup,
            text="Generate Password",
            command=generate
        )

        generate_btn.pack(pady=10)

        def save_password():

            site = site_entry.get()
            username = username_entry.get()
            password = password_entry.get()

            if not site or not username or not password:

                messagebox.showerror(
                    "Error",
                    "All fields required"
                )

                return

            if not is_strong(password):

                messagebox.showerror(
                    "Weak Password",
                    "Password not strong enough"
                )

                return

            encrypted, iv = encrypt_password(
                self.key,
                password
            )

            conn = sqlite3.connect(DB_NAME)
            c = conn.cursor()

            c.execute(
                """
                INSERT INTO vault
                (
                    site,
                    username,
                    encrypted_password,
                    iv
                )
                VALUES (?, ?, ?, ?)
                """,
                (
                    site,
                    username,
                    encrypted,
                    iv
                )
            )

            conn.commit()
            conn.close()

            popup.destroy()

            self.load_passwords()

            messagebox.showinfo(
                "Success",
                "Password Added"
            )

        save_btn = ctk.CTkButton(
            popup,
            text="Save",
            width=200,
            height=45,
            command=save_password
        )

        save_btn.pack(pady=20)

    # ================= DELETE =================
    def delete_password(self, password_id):

        confirm = messagebox.askyesno(
            "Delete",
            "Are you sure?"
        )

        if confirm:

            conn = sqlite3.connect(DB_NAME)
            c = conn.cursor()

            c.execute(
                "DELETE FROM vault WHERE id=?",
                (password_id,)
            )

            conn.commit()
            conn.close()

            self.load_passwords()

    # ================= COPY =================
    def copy_password(self, password):

        pyperclip.copy(password)

        messagebox.showinfo(
            "Copied",
            "Password copied to clipboard"
        )

    # ================= SEARCH =================
    def search_passwords(self, event=None):

        keyword = self.search_entry.get().lower()

        for widget in self.main_frame.winfo_children():
            widget.destroy()

        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()

        query = f"%{keyword}%"

        c.execute(
            """
            SELECT * FROM vault
            WHERE site LIKE ?
            OR username LIKE ?
            """,
            (query, query)
        )

        rows = c.fetchall()

        conn.close()

        for row in rows:
            self.create_password_card(row)

    # ================= CHECKUP =================
    def show_checkup(self):

        for widget in self.main_frame.winfo_children():
            widget.destroy()

        title = ctk.CTkLabel(
            self.main_frame,
            text="Security Checkup",
            font=("Arial", 30, "bold")
        )

        title.pack(pady=30)

        weak_count = 0

        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()

        c.execute("SELECT * FROM vault")

        rows = c.fetchall()

        conn.close()

        for row in rows:

            password = decrypt_password(
                self.key,
                row[3],
                row[4]
            )

            if not is_strong(password):
                weak_count += 1

        result = ctk.CTkLabel(
            self.main_frame,
            text=f"Weak Passwords Found: {weak_count}",
            font=("Arial", 22)
        )

        result.pack(pady=20)

    # ================= SETTINGS =================
    def show_settings(self):

        for widget in self.main_frame.winfo_children():
            widget.destroy()

        title = ctk.CTkLabel(
            self.main_frame,
            text="Settings",
            font=("Arial", 30, "bold")
        )

        title.pack(pady=30)

        dark_btn = ctk.CTkButton(
            self.main_frame,
            text="Dark Mode",
            width=250,
            height=50,
            command=lambda:
            ctk.set_appearance_mode("dark")
        )

        dark_btn.pack(pady=20)

        light_btn = ctk.CTkButton(
            self.main_frame,
            text="Light Mode",
            width=250,
            height=50,
            command=lambda:
            ctk.set_appearance_mode("light")
        )

        light_btn.pack(pady=20)

# ================= RUN =================
if __name__ == "__main__":

    app = PasswordManagerGUI()

    app.mainloop()
