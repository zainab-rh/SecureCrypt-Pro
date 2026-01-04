import os
import logging
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

# Using cryptography.hazmat because it's standard for senior-level security labs
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

# Simple logger for debugging encryption/decryption flows
logging.basicConfig(
    filename='crypto_debug.log',
    level=logging.INFO,
    format='%(levelname)s | %(asctime)s | %(message)s'
)

class SecureFolderApp:
    def __init__(self, root):
        self.root = root
        self.root.title("AES-GCM File Security Tool")
        self.root.geometry("550x450")
        
        # Security Constants
        # 600,000 iterations is currently recommended by OWASP for PBKDF2-HMAC-SHA256
        self.ITERATIONS = 600000 
        self.SALT_SIZE = 16   # 128-bit salt
        self.NONCE_SIZE = 12  # Standard nonce size for AES-GCM
        
        self.setup_ui()

    def setup_ui(self):
        """Organizing the UI into tabs for a cleaner 'Tool' feel"""
        self.tabs = ttk.Notebook(self.root)
        self.tabs.pack(expand=True, fill="both", padx=5, pady=5)

        self.enc_tab = ttk.Frame(self.tabs)
        self.dec_tab = ttk.Frame(self.tabs)
        self.util_tab = ttk.Frame(self.tabs)

        self.tabs.add(self.enc_tab, text="Encrypt")
        self.tabs.add(self.dec_tab, text="Decrypt")
        self.tabs.add(self.util_tab, text="Utilities")

        # Encryption Tab Layout
        enc_frame = ttk.LabelFrame(self.enc_tab, text="File Encryption", padding=10)
        enc_frame.pack(fill="both", expand=True, padx=10, pady=10)

        self.enc_path_var = tk.StringVar()
        ttk.Label(enc_frame, text="Target File:").grid(row=0, column=0, sticky="w")
        ttk.Entry(enc_frame, textvariable=self.enc_path_var, width=40).grid(row=1, column=0, pady=5)
        ttk.Button(enc_frame, text="Browse", command=lambda: self._browse(self.enc_path_var)).grid(row=1, column=1, padx=5)

        self.enc_pass_var = tk.StringVar()
        ttk.Label(enc_frame, text="Master Password:").grid(row=2, column=0, sticky="w", pady=(10,0))
        ttk.Entry(enc_frame, textvariable=self.enc_pass_var, show="*").grid(row=3, column=0, sticky="ew")

        ttk.Button(enc_frame, text="Start Encryption", command=self.run_encryption).grid(row=4, column=0, pady=20)

        # Decryption Tab Layout
        dec_frame = ttk.LabelFrame(self.dec_tab, text="File Decryption", padding=10)
        dec_frame.pack(fill="both", expand=True, padx=10, pady=10)

        self.dec_path_var = tk.StringVar()
        ttk.Label(dec_frame, text="Encrypted (.enc) File:").grid(row=0, column=0, sticky="w")
        ttk.Entry(dec_frame, textvariable=self.dec_path_var, width=40).grid(row=1, column=0, pady=5)
        ttk.Button(dec_frame, text="Browse", command=lambda: self._browse(self.dec_path_var)).grid(row=1, column=1, padx=5)

        self.dec_pass_var = tk.StringVar()
        ttk.Label(dec_frame, text="Password:").grid(row=2, column=0, sticky="w", pady=(10,0))
        ttk.Entry(dec_frame, textvariable=self.dec_pass_var, show="*").grid(row=3, column=0, sticky="ew")

        ttk.Button(dec_frame, text="Start Decryption", command=self.run_decryption).grid(row=4, column=0, pady=20)

        # Keygen Utility (just in case user wants a random hex key)
        util_frame = ttk.LabelFrame(self.util_tab, text="Key Tools", padding=10)
        util_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        self.key_out = tk.StringVar()
        ttk.Label(util_frame, text="Generate Secure 256-bit Hex Key:").pack(pady=5)
        ttk.Entry(util_frame, textvariable=self.key_out, state="readonly", width=50).pack(pady=5)
        ttk.Button(util_frame, text="Generate", command=lambda: self.key_out.set(os.urandom(32).hex())).pack()

        # Simple progress feedback for better UX
        self.progress = ttk.Progressbar(self.root, orient="horizontal", mode="determinate")
        self.progress.pack(fill="x", side="bottom", padx=10, pady=5)

    def _browse(self, var):
        f = filedialog.askopenfilename()
        if f: var.set(f)

    def _get_key(self, password, salt):
        """
        Derives a 32-byte (256-bit) key from a variable length password.
        Using PBKDF2 with SHA256 as the PRF.
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=self.ITERATIONS,
            backend=default_backend()
        )
        return kdf.derive(password.encode())

    def run_encryption(self):
        f_path = self.enc_path_var.get()
        pwd = self.enc_pass_var.get()

        if not f_path or not pwd:
            messagebox.showwarning("Input Error", "File and Password are required.")
            return

        try:
            self.progress['value'] = 20
            p_file = Path(f_path)
            
            # Use os.urandom for CSPRNG (Cryptographically Secure Pseudo-Random Number Generator)
            salt = os.urandom(self.SALT_SIZE)
            key = self._get_key(pwd, salt)
            nonce = os.urandom(self.NONCE_SIZE)
            
            # Must read in 'rb' mode to handle non-text files correctly
            with open(p_file, 'rb') as f:
                data = f.read()
            
            self.progress['value'] = 50
            # AES-GCM is an AEAD mode; it handles both encryption and authentication tags
            aesgcm = AESGCM(key)
            ciphertext = aesgcm.encrypt(nonce, data, None) 

            # Output file structure: [16b Salt][12b Nonce][Ciphertext + 16b Auth Tag]
            out_name = p_file.with_suffix(p_file.suffix + ".enc")
            with open(out_name, 'wb') as f:
                f.write(salt + nonce + ciphertext)

            self.progress['value'] = 100
            logging.info(f"Encrypted file saved: {out_name.name}")
            messagebox.showinfo("Success", f"Encrypted as:\n{out_name.name}")
            
        except Exception as e:
            logging.error(f"Error during encryption: {str(e)}")
            messagebox.showerror("System Error", f"Something went wrong: {e}")
        finally:
            self.progress['value'] = 0

    def run_decryption(self):
        f_path = self.dec_path_var.get()
        pwd = self.dec_pass_var.get()

        if not f_path or not pwd:
            return

        try:
            self.progress['value'] = 20
            with open(f_path, 'rb') as f:
                raw_data = f.read()

            # Manual slicing of the binary header
            salt = raw_data[:self.SALT_SIZE]
            nonce = raw_data[self.SALT_SIZE:self.SALT_SIZE+self.NONCE_SIZE]
            ct = raw_data[self.SALT_SIZE+self.NONCE_SIZE:]

            self.progress['value'] = 40
            key = self._get_key(pwd, salt)
            
            aesgcm = AESGCM(key)
            # Decrypt method will verify the auth tag automatically. 
            # If the password is wrong or file tampered, it raises InvalidTag.
            pt = aesgcm.decrypt(nonce, ct, None)

            # Cleanup filename (stripping .enc)
            p_path = Path(f_path)
            out_name = p_path.stem if p_path.suffix == ".enc" else f"decrypted_{p_path.name}"
            out_path = p_path.with_name(out_name)

            with open(out_path, 'wb') as f:
                f.write(pt)

            self.progress['value'] = 100
            messagebox.showinfo("Success", "Decryption complete. Integrity verified.")
            
        except Exception:
            # We catch all exceptions here but log it as a likely Auth failure
            logging.warning("Decryption failed. Potential bad password or corrupted file.")
            messagebox.showerror("Auth Failure", "Invalid password or the file has been modified.")
        finally:
            self.progress['value'] = 0

if __name__ == "__main__":
    root = tk.Tk()
    # Adding a bit of transparency for a slightly more modern look
    try:
        root.attributes('-alpha', 0.98) 
    except:
        pass
        
    app = SecureFolderApp(root)
    root.mainloop()
