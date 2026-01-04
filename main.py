import os
import logging
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

# Cryptography imports
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

# Setup basic logging
logging.basicConfig(
    filename='app_log.txt',
    level=logging.INFO,
    format='%(asctime)s - %(message)s'
)

class FileEncryptorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("File Encryptor Tool")
        self.root.geometry("600x450")
        
        # Style configuration
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        # Constants
        self.ITERATIONS = 600000 # Recommended iterations for PBKDF2
        self.SALT_SIZE = 16
        self.NONCE_SIZE = 12
        
        self.setup_ui()

    def setup_ui(self):
        # Create tabs
        tab_control = ttk.Notebook(self.root)
        
        self.tab_encrypt = ttk.Frame(tab_control)
        self.tab_decrypt = ttk.Frame(tab_control)
        self.tab_keygen = ttk.Frame(tab_control)
        
        tab_control.add(self.tab_encrypt, text='Encrypt')
        tab_control.add(self.tab_decrypt, text='Decrypt')
        tab_control.add(self.tab_keygen, text='Generate Key')
        tab_control.pack(expand=1, fill="both", padx=10, pady=10)
        
        self.build_encrypt_tab()
        self.build_decrypt_tab()
        self.build_keygen_tab()

    def build_encrypt_tab(self):
        frame = ttk.LabelFrame(self.tab_encrypt, text="Encryption Settings", padding=15)
        frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # File selection
        ttk.Label(frame, text="Select File:").pack(anchor='w')
        self.enc_file_path = tk.StringVar()
        entry_row = ttk.Frame(frame)
        entry_row.pack(fill='x', pady=5)
        ttk.Entry(entry_row, textvariable=self.enc_file_path).pack(side='left', fill='x', expand=True)
        ttk.Button(entry_row, text="Browse", command=lambda: self.browse_file(self.enc_file_path)).pack(side='right', padx=5)
        
        # Password
        ttk.Label(frame, text="Password:").pack(anchor='w', pady=(10,0))
        self.enc_password = tk.StringVar()
        ttk.Entry(frame, textvariable=self.enc_password, show="*").pack(fill='x', pady=5)
        
        # Execute
        ttk.Button(frame, text="Encrypt File", command=self.do_encrypt).pack(pady=20)
        self.enc_status = ttk.Label(frame, text="Ready", foreground="blue")
        self.enc_status.pack()

    def build_decrypt_tab(self):
        frame = ttk.LabelFrame(self.tab_decrypt, text="Decryption Settings", padding=15)
        frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # File selection
        ttk.Label(frame, text="Select Encrypted File:").pack(anchor='w')
        self.dec_file_path = tk.StringVar()
        entry_row = ttk.Frame(frame)
        entry_row.pack(fill='x', pady=5)
        ttk.Entry(entry_row, textvariable=self.dec_file_path).pack(side='left', fill='x', expand=True)
        ttk.Button(entry_row, text="Browse", command=lambda: self.browse_file(self.dec_file_path)).pack(side='right', padx=5)
        
        # Password
        ttk.Label(frame, text="Password:").pack(anchor='w', pady=(10,0))
        self.dec_password = tk.StringVar()
        ttk.Entry(frame, textvariable=self.dec_password, show="*").pack(fill='x', pady=5)
        
        # Execute
        ttk.Button(frame, text="Decrypt File", command=self.do_decrypt).pack(pady=20)
        self.dec_status = ttk.Label(frame, text="Ready", foreground="blue")
        self.dec_status.pack()

    def build_keygen_tab(self):
        # A simple utility to generate a random strong password/key if needed
        frame = ttk.LabelFrame(self.tab_keygen, text="Key Generator", padding=15)
        frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        ttk.Label(frame, text="Click below to generate a secure random token (32 bytes hex)").pack(pady=10)
        self.generated_key_var = tk.StringVar()
        ttk.Entry(frame, textvariable=self.generated_key_var, state="readonly").pack(fill='x', pady=5)
        ttk.Button(frame, text="Generate", command=lambda: self.generated_key_var.set(os.urandom(32).hex())).pack(pady=5)

    def browse_file(self, var):
        filename = filedialog.askopenfilename()
        if filename:
            var.set(filename)

    def derive_key(self, password: str, salt: bytes) -> bytes:
        # PBKDF2 to turn the user password into a 32-byte AES key
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=self.ITERATIONS,
            backend=default_backend()
        )
        return kdf.derive(password.encode())

    def do_encrypt(self):
        file_path = self.enc_file_path.get()
        password = self.enc_password.get()
        
        if not file_path or not password:
            messagebox.showerror("Error", "Please select a file and enter a password.")
            return

        try:
            # Read file data
            with open(file_path, 'rb') as f:
                plaintext = f.read()

            # Generate salt and key
            salt = os.urandom(self.SALT_SIZE)
            key = self.derive_key(password, salt)
            
            # Using AES-GCM (Galois/Counter Mode) because it provides authenticated encryption.
            aesgcm = AESGCM(key)
            nonce = os.urandom(self.NONCE_SIZE)
            
            # Encrypt
            ciphertext = aesgcm.encrypt(nonce, plaintext, None)
            
            # Save format: [SALT (16)] + [NONCE (12)] + [CIPHERTEXT]
            output_path = file_path + ".enc"
            with open(output_path, 'wb') as f:
                f.write(salt + nonce + ciphertext)
            
            logging.info(f"Encrypted {file_path}")
            self.enc_status.config(text=f"Success! Saved as {os.path.basename(output_path)}", foreground="green")
            messagebox.showinfo("Success", "File encrypted successfully!")
            
        except Exception as e:
            logging.error(f"Encryption failed: {e}")
            messagebox.showerror("Error", f"Encryption failed: {str(e)}")

    def do_decrypt(self):
        file_path = self.dec_file_path.get()
        password = self.dec_password.get()
        
        if not file_path or not password:
            messagebox.showerror("Error", "Please select a file and enter a password.")
            return
            
        try:
            with open(file_path, 'rb') as f:
                file_data = f.read()
            
            # Extract components
            # Format was: SALT (16) + NONCE (12) + CIPHERTEXT
            if len(file_data) < 28:
                raise ValueError("File is too small/corrupted")
                
            salt = file_data[:self.SALT_SIZE]
            nonce = file_data[self.SALT_SIZE:self.SALT_SIZE+self.NONCE_SIZE]
            ciphertext = file_data[self.SALT_SIZE+self.NONCE_SIZE:]
            
            # Derive key again
            key = self.derive_key(password, salt)
            
            # Decrypt
            aesgcm = AESGCM(key)
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            
            # Restore original filename (remove .enc)
            if file_path.endswith(".enc"):
                output_path = file_path[:-4]
            else:
                output_path = file_path + ".decrypted"
                
            with open(output_path, 'wb') as f:
                f.write(plaintext)
                
            logging.info(f"Decrypted {file_path}")
            self.dec_status.config(text=f"Success! Restored {os.path.basename(output_path)}", foreground="green")
            messagebox.showinfo("Success", "File decrypted successfully!")
            
        except Exception as e:
            # AES-GCM raises an exception if the tag doesn't match (wrong password or tampered file)
            logging.error(f"Decryption failed: {e}")
            messagebox.showerror("Error", "Decryption failed. Wrong password or corrupted file.")

if __name__ == "__main__":
    root = tk.Tk()
    app = FileEncryptorApp(root)
    root.mainloop()
