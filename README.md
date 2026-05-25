# Password Vault Manager

**Password Vault Manager** is a modern, 100% local, and private GUI application for securely storing and managing your credentials. Built with Python and customtkinter, it serves as a digital fortress for your sensitive data, ensuring that your keys never leave the device.

## ✨ Features

* **Modern User Interface:** A sleek, responsive design featuring Dark/Light mode toggles, built with CustomTkinter.
* **Zero-Knowledge Architecture:** Designed so that your master password is never stored directly; it is used only to derive your encryption keys.
* **Strong Password Generator:** Quickly create robust, randomized passwords containing a mix of letters, numbers, and special characters.
* **Security Checkup:** Built-in auditing tool to scan your vault and detect weak passwords.
* **Seamless Clipboard Integration:** Copy passwords to your clipboard with a single click.

## 🔒 Security Architecture

This application is built on core security pillars—robust hashing and authenticated encryption.

* **Key Derivation:** Uses PBKDF2‑SHA256 with a unique, randomized salt and 100,000 iterations to derive a secure cryptographic key from your master password. This slows down brute-force attacks.
* **AEAD Encryption:** Employs AES-GCM (Galois/Counter Mode) to ensure both the confidentiality and the integrity of every entry.
* **Cryptographic Nonces:** A fresh nonce (Initialization Vector) is generated for every encryption call to ensure that identical passwords encrypt into completely different ciphertexts.
* **Encrypted Local Storage:** Data is persisted in a local SQLite database, where sensitive fields are stored strictly as encrypted binary blobs (ciphertext).

## 🚀 Installation & Setup

### Prerequisites
Make sure you have Python 3.x installed on your system.

### 1. Clone the repository
```bash
git clone https://github.com/yourusername/passwrd-valut-manager.git
cd passwrd-valut-manager
```

### 2. Install Dependencies

Install the required third-party Python libraries using pip:

```bash
pip install customtkinter cryptography pyperclip
```

### 3. Run the Application

```bash
python main.py
```

(Note: Ensure your script file is named main.py, or adjust the command to match your filename).

## 📖 Usage

* **Launch the App:** On the first run, the app will automatically initialize a secure vault.db SQLite database file in the exact same directory and generate your unique cryptographic salt.
* **Add a Password:** Click the "Add" button in the top right. Fill in the website, username, and type a password (or click "Generate Password"). Click "Save".
* **Manage Entries:** Your saved credentials will appear on the main dashboard. You can View, Copy, or Delete them using the provided buttons.
* **Security Checkup:** Navigate to the "Checkup" tab on the left sidebar to audit your saved credentials for any weak or vulnerable passwords.
* **Settings:** Use the "Settings" tab to toggle between Light and Dark interface themes.

## ⚠️ Disclaimer

**For Educational and Personal Use:** While this application implements standard encryption protocols like AES-GCM and PBKDF2, it utilizes a hardcoded master password ("1234") in its current template. You must modify the code to prompt the user for a secure master password upon startup before using this to store real, highly sensitive credentials.
