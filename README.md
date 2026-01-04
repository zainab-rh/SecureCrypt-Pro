# AES-GCM File Security Utility

This project is a Python-based implementation of an authenticated encryption tool. It was developed to provide a secure way to encrypt files using **AES-256 in Galois/Counter Mode (GCM)**, ensuring both confidentiality and data integrity.

## Project Overview
The main goal was to create a functional GUI tool that follows modern cryptographic standards. Most basic tutorials use AES-CBC, but for this project, I chose **AES-GCM** because it includes an authentication tag. This prevents "bit-flipping" attacks and ensures that if even a single byte of the encrypted file is modified, the decryption will fail rather than producing corrupted data.

### Technical Implementation
* **KDF:** PBKDF2-HMAC-SHA256 with 600,000 iterations. This is aligned with current OWASP security recommendations to slow down brute-force attempts.
* **Entropy:** Salts and nonces are generated using `os.urandom()` to ensure they are cryptographically secure.
* **Data Integrity:** The tool verifies the GCM authentication tag during the decryption phase. If the password is wrong or the file has been tampered with, the app triggers a `cryptography.exceptions.InvalidTag` error, which I’ve handled with a user-friendly alert.



## Binary File Format
To keep the tool portable, the metadata required for decryption is stored directly in the output file header. The salt and nonce are not secret, so they are prepended to the ciphertext.

**Layout:** `[16 bytes: Salt] + [12 bytes: Nonce] + [Variable: Ciphertext + 16-byte Auth Tag]`

---

## Setup & Requirements
This tool requires Python 3.8+ and the `cryptography` library.

1. **Install dependencies:**
   ```bash
   pip install cryptography
## File Structure
The application appends the Salt and Nonce to the beginning of the file so they can be retrieved during decryption.

```text
[SALT (16 bytes)] + [NONCE (12 bytes)] + [CIPHERTEXT]
```


2. **Run the application: **
 ``` python
python main.py
 ```

## Usage Instructions

### Encryption Tab
1. Select a file using the **Browse** button.
2. Enter a strong master password.
3. Click **Start Encryption**. The application will generate a unique salt and nonce, encrypt the data, and save the result with a `.enc` extension in the same directory.

### Decryption Tab
1. Select the `.enc` file you wish to restore.
2. Enter the original password.
3. Click **Start Decryption**. The app will verify the **GCM integrity tag**; if the password is correct and the file hasn't been tampered with, the original file will be restored.

### Utilities
I included a small utility tab to generate 256-bit random hex keys. This can be used if you need a high-entropy key instead of a standard password. This generates a cryptographically secure random value using `os.urandom()`.

### Logging
All operations are logged to `crypto_debug.log`. This includes timestamps for successful encryptions and warnings for failed decryption attempts (useful for tracking if someone is trying to guess the password or if the file header has been corrupted).
