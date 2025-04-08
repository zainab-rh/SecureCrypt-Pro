# SecureCrypt Pro - File Encryption Suite


A secure desktop application for file encryption/decryption implementing modern cryptographic standards, designed with security best practices and audit capabilities.


## Features

### Encryption Algorithms
- AES-256-CBC & ChaCha20 implementations
- PBKDF2 key derivation (480,000 iterations)
- Secure salt generation & metadata protection
- Constant-time comparison for authentication

### Application Features
- Audit logging for all operations
- Password strength meter
- Progress visualization
- Cross-platform compatibility

### Security Features
- Secure key generation and storage
- Tamper detection system
- Exception handling for cryptographic operations
- GUI input validation

## Installation

1. **Requirements**:
   - Python 3.8+
   - Tcl/Tk (for GUI)

2. **Install dependencies**:
```bash
pip install cryptography tkinter
