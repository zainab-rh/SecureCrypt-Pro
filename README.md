
# 🔒 SecureCrypt Pro - File Encryption Tool
A Python-based file encryption tool developed as a cryptography project. This application uses **AES-256-GCM** (Galois/Counter Mode) to provide both confidentiality and data integrity (authenticated encryption).

## Key Features

### Cryptographic Implementation
* **Algorithm:** AES-256-GCM (Authenticated Encryption).
    * *Why GCM?* Unlike CBC, GCM does not require padding (preventing Padding Oracle attacks) and includes built-in integrity checks to detect if a file has been tampered with.
* **Key Derivation:** PBKDF2-HMAC-SHA256.
    * Uses **600,000 iterations** (OWASP recommended) to prevent brute-force attacks on passwords.
* **Randomness:** Uses `os.urandom` for generating cryptographic salts (16 bytes) and nonces (12 bytes).

### Application Features
* **GUI:** Built with Tkinter (`ttk`) for a native look and feel.
* **Logging:** Automatically logs encryption/decryption events to `app_log.txt` for audit purposes.
* **Key Generator:** Includes a utility to generate cryptographically strong 32-byte hex keys.
* **Error Handling:** Catches decryption errors (wrong password or corrupted/tampered files) to prevent crashes.

## Technical Highlights

The core logic uses the `cryptography` library to ensure standard compliance.

**Key Derivation Snippet:**

```python
# Deriving a 32-byte AES key from a user password
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=600000, # High iteration count for security
    backend=default_backend()
)
key = kdf.derive(password.encode())

### File Structure
The application appends the Salt and Nonce to the beginning of the file so they can be retrieved during decryption.

```text
[SALT (16 bytes)] + [NONCE (12 bytes)] + [CIPHERTEXT]


## Installation

**Requirements:**
* Python 3.8+ (verified on 3.10.6)
* `cryptography` library

**Setup:**

```bash
pip install cryptography

## How to use

### Encrypt
Select a file, enter a strong password, and click "Encrypt". The file will be saved with a `.enc` extension.

### Decrypt
Select the `.enc` file and enter the original password. The app will verify the integrity tag and restore the original file.
