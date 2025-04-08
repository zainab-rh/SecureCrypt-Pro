import os
import logging
import hashlib
from pathlib import Path
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from typing import Optional, Tuple

# Security Configuration
PBKDF2_ITERATIONS = 480000

# Style Configuration
BG_COLOR = "#2E2E2E"
FG_COLOR = "#FFFFFF"
ACCENT_COLOR = "#4A90D9"
ENTRY_BG = "#404040"
FONT = ("Segoe UI", 10)
BUTTON_STYLE = {
    "background": ACCENT_COLOR,
    "foreground": FG_COLOR,
    "font": FONT,
    "borderwidth": 0
}

# Custom Exceptions
class SecurityError(Exception):
    pass

class CryptoUtils:
    @staticmethod
    def constant_time_compare(val1: bytes, val2: bytes) -> bool:
        """Constant-time comparison to prevent timing attacks"""
        return len(val1) == len(val2) and hashlib.sha256(val1).digest() == hashlib.sha256(val2).digest()

class KeyManager:
    def generate_key(self, password: Optional[str] = None) -> Tuple[bytes, bytes]:
        """Generate encryption key with optional password derivation"""
        salt = os.urandom(16)
        if password:
            key = self.derive_key_from_password(password, salt)
            return key, salt
        return os.urandom(32), salt

    def derive_key_from_password(self, password: str, salt: bytes) -> bytes:
        """Derive a key from a password and salt"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=PBKDF2_ITERATIONS,
            backend=default_backend()
        )
        return kdf.derive(password.encode())

class FileEncryptor:
    def __init__(self, algorithm: str = 'AES-256-CBC'):
        self.algorithm = algorithm

    def encrypt_file(self, input_path: Path, output_path: Path, key: bytes) -> None:
        iv = os.urandom(16)
        data = input_path.read_bytes()
        original_extension = input_path.suffix.encode()
        metadata = original_extension

        if self.algorithm == 'AES-256-CBC':
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), default_backend())
            padder = padding.PKCS7(128).padder()
            padded_data = padder.update(data) + padder.finalize()
            encrypted = iv + cipher.encryptor().update(padded_data)
        elif self.algorithm == 'ChaCha20':
            cipher = Cipher(algorithms.ChaCha20(key, iv), None, default_backend())
            encrypted = iv + cipher.encryptor().update(data)

        encrypted_with_metadata = len(metadata).to_bytes(4, 'big') + metadata + encrypted
        output_path.write_bytes(encrypted_with_metadata)

    def decrypt_file(self, input_path: Path, output_path: Path, key: bytes) -> None:
        data = input_path.read_bytes()
        metadata_length = int.from_bytes(data[:4], 'big')
        metadata = data[4:4 + metadata_length]
        original_extension = metadata.decode()
        encrypted_data = data[4 + metadata_length:]

        iv = encrypted_data[:16]
        ciphertext = encrypted_data[16:]

        if self.algorithm == 'AES-256-CBC':
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), default_backend())
            decrypted = cipher.decryptor().update(ciphertext)
            unpadder = padding.PKCS7(128).unpadder()
            plaintext = unpadder.update(decrypted) + unpadder.finalize()
        elif self.algorithm == 'ChaCha20':
            cipher = Cipher(algorithms.ChaCha20(key, iv), None, default_backend())
            plaintext = cipher.decryptor().update(ciphertext)

        output_path = output_path.with_name(output_path.stem + "_dec" + original_extension)
        output_path.write_bytes(plaintext)

class AuditLogger:
    def __init__(self):
        logging.basicConfig(
            filename='crypto_audit.log',
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )

    def log_operation(self, action: str, file: Path, status: str = "SUCCESS") -> None:
        logging.info(f"{action} on {file} - {status}")

class ModernGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("SecureCrypt Pro")
        self.geometry("800x600")
        self.configure(bg=BG_COLOR)
        self._configure_styles()
        
    def _configure_styles(self):
        style = ttk.Style(self)
        style.theme_use('clam')
        
        style.configure('TNotebook', background=BG_COLOR)
        style.configure('TNotebook.Tab', 
                      background=BG_COLOR,
                      foreground=FG_COLOR,
                      padding=[10, 5],
                      font=FONT)
        style.map('TNotebook.Tab', 
                 background=[('selected', ACCENT_COLOR)],
                 foreground=[('selected', FG_COLOR)])
        
        style.configure('TFrame', background=BG_COLOR)
        style.configure('TLabel', background=BG_COLOR, foreground=FG_COLOR, font=FONT)
        style.configure('TEntry', fieldbackground=ENTRY_BG, foreground=FG_COLOR, insertcolor=FG_COLOR)
        style.configure('TButton', **BUTTON_STYLE)
        style.map('TButton', 
                 background=[('active', '#357ABD'), ('disabled', '#404040')],
                 foreground=[('disabled', '#808080')])
        
        style.configure('Header.TLabel', font=("Segoe UI", 12, "bold"))
        style.configure('Success.TLabel', foreground="#4CAF50")
        style.configure('Error.TLabel', foreground="#F44336")
        style.configure('Success.Horizontal.TProgressbar', background='#4CAF50')
        style.configure('Warning.Horizontal.TProgressbar', background='#FFC107')
        style.configure('Error.Horizontal.TProgressbar', background='#F44336')

class CryptoGUI(ModernGUI):
    def __init__(self):
        super().__init__()
        self.encryptor = FileEncryptor()
        self.key_manager = KeyManager()
        self.logger = AuditLogger()
        self._create_widgets()
        self._setup_validation()

    def _create_widgets(self):
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill='both', expand=True, padx=10, pady=10)

        self._create_encryption_tab()
        self._create_decryption_tab()
        self._create_keygen_tab()
        
        self.status_bar = ttk.Label(self, style='Success.TLabel')
        self.status_bar.pack(side='bottom', fill='x')

    def _create_section(self, parent, title):
        frame = ttk.LabelFrame(parent, text=title, padding=10)
        frame.pack(fill='x', pady=5, padx=5)
        return frame

    def _create_encryption_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="🔒 Encrypt")
        container = ttk.Frame(tab)
        container.pack(padx=20, pady=20, fill='both', expand=True)

        # File Selection
        file_frame = self._create_section(container, "File Selection")
        ttk.Label(file_frame, text="Source File:").grid(row=0, column=0, sticky='e')
        self.encrypt_file_entry = ttk.Entry(file_frame, width=50)
        self.encrypt_file_entry.grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(file_frame, text="📁 Browse", command=self._select_encrypt_file).grid(row=0, column=2)

        # Key Management
        key_frame = self._create_section(container, "Encryption Key")
        ttk.Label(key_frame, text="Key File:").grid(row=0, column=0, sticky='e')
        self.encrypt_key_entry = ttk.Entry(key_frame, width=50)
        self.encrypt_key_entry.grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(key_frame, text="📁 Browse", command=self._select_encrypt_key).grid(row=0, column=2)
        
        ttk.Label(key_frame, text="Password:").grid(row=1, column=0, sticky='e')
        self.encrypt_password_entry = ttk.Entry(key_frame, show="•")
        self.encrypt_password_entry.grid(row=1, column=1, padx=5, pady=5, sticky='ew')

        # Actions
        action_frame = self._create_section(container, "Actions")
        self.encrypt_progress = ttk.Progressbar(action_frame, orient="horizontal", mode="determinate")
        self.encrypt_progress.pack(pady=10)
        ttk.Button(action_frame, text="🚀 Start Encryption", command=self._perform_encryption).pack(pady=10)

    def _create_decryption_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="🔓 Decrypt")
        container = ttk.Frame(tab)
        container.pack(padx=20, pady=20, fill='both', expand=True)

        # File Selection
        file_frame = self._create_section(container, "File Selection")
        ttk.Label(file_frame, text="Encrypted File:").grid(row=0, column=0, sticky='e')
        self.decrypt_file_entry = ttk.Entry(file_frame, width=50)
        self.decrypt_file_entry.grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(file_frame, text="📁 Browse", command=self._select_decrypt_file).grid(row=0, column=2)

        # Key Management
        key_frame = self._create_section(container, "Decryption Key")
        ttk.Label(key_frame, text="Key File:").grid(row=0, column=0, sticky='e')
        self.decrypt_key_entry = ttk.Entry(key_frame, width=50)
        self.decrypt_key_entry.grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(key_frame, text="📁 Browse", command=self._select_decrypt_key).grid(row=0, column=2)
        
        ttk.Label(key_frame, text="Password:").grid(row=1, column=0, sticky='e')
        self.decrypt_password_entry = ttk.Entry(key_frame, show="•")
        self.decrypt_password_entry.grid(row=1, column=1, padx=5, pady=5, sticky='ew')

        # Actions
        action_frame = self._create_section(container, "Actions")
        self.decrypt_progress = ttk.Progressbar(action_frame, orient="horizontal", mode="determinate")
        self.decrypt_progress.pack(pady=10)
        ttk.Button(action_frame, text="🚀 Start Decryption", command=self._perform_decryption).pack(pady=10)

    def _create_keygen_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="🔑 Generate Key")
        container = ttk.Frame(tab)
        container.pack(padx=20, pady=20, fill='both', expand=True)

        # Password Input
        pass_frame = self._create_section(container, "Password Settings")
        ttk.Label(pass_frame, text="Password:").grid(row=0, column=0, sticky='e')
        self.keygen_password_entry = ttk.Entry(pass_frame, show="•")
        self.keygen_password_entry.grid(row=0, column=1, padx=5, pady=5, sticky='ew')
        
        # Strength Meter
        self.strength_meter = ttk.Progressbar(pass_frame, orient="horizontal", mode="determinate")
        self.strength_meter.grid(row=1, column=1, sticky='ew', padx=5)
        self.keygen_password_entry.bind("<KeyRelease>", self._update_strength_meter)

        # Save Location
        save_frame = self._create_section(container, "Save Location")
        ttk.Label(save_frame, text="Save To:").grid(row=0, column=0, sticky='e')
        self.keygen_file_entry = ttk.Entry(save_frame, width=50)
        self.keygen_file_entry.grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(save_frame, text="📁 Browse", command=self._select_keygen_file).grid(row=0, column=2)

        # Generate Button
        action_frame = self._create_section(container, "Actions")
        ttk.Button(action_frame, text="⚡ Generate Key", command=self._perform_keygen).pack(pady=10)

    def _update_strength_meter(self, event):
        password = self.keygen_password_entry.get()
        strength = min(len(password) * 10, 100)
        self.strength_meter["value"] = strength
        self.strength_meter["style"] = "Error.Horizontal.TProgressbar" if strength < 50 else \
                                      "Warning.Horizontal.TProgressbar" if strength < 75 else \
                                      "Success.Horizontal.TProgressbar"

    def _show_status(self, message, success=True):
        if success:
            messagebox.showinfo("Success", message)
        else:
            messagebox.showerror("Error", message)

    # File selection methods
    def _select_encrypt_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            self.encrypt_file_entry.delete(0, tk.END)
            self.encrypt_file_entry.insert(0, file_path)

    def _select_encrypt_key(self):
        key_path = filedialog.askopenfilename()
        if key_path:
            self.encrypt_key_entry.delete(0, tk.END)
            self.encrypt_key_entry.insert(0, key_path)

    def _select_decrypt_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            self.decrypt_file_entry.delete(0, tk.END)
            self.decrypt_file_entry.insert(0, file_path)

    def _select_decrypt_key(self):
        key_path = filedialog.askopenfilename()
        if key_path:
            self.decrypt_key_entry.delete(0, tk.END)
            self.decrypt_key_entry.insert(0, key_path)

    def _select_keygen_file(self):
        key_path = filedialog.asksaveasfilename(defaultextension=".key", filetypes=[("Key Files", "*.key")])
        if key_path:
            self.keygen_file_entry.delete(0, tk.END)
            self.keygen_file_entry.insert(0, key_path)

    # Core functionality methods
    def _perform_keygen(self):
        try:
            password = self.keygen_password_entry.get()
            key_path = self.keygen_file_entry.get()
            
            if not key_path:
                self._show_status("Please specify a file to save the key!", False)
                return

            key, salt = self.key_manager.generate_key(password)
            with open(key_path, "wb") as key_file:
                key_file.write(salt + key)

            self.logger.log_operation("Key Generation", Path(key_path), "SUCCESS")
            self._show_status(f"Key generated successfully: {key_path}")
            
        except Exception as e:
            self.logger.log_operation("Key Generation", Path(key_path), f"FAILED: {str(e)}")
            self._show_status(f"Key generation failed: {str(e)}", False)

    def _perform_encryption(self):
        try:
            input_file = self.encrypt_file_entry.get()
            key_file = self.encrypt_key_entry.get()
            password = self.encrypt_password_entry.get()
            
            if not input_file or not key_file:
                self._show_status("Please select both file and key!", False)
                return

            if password:
                with open(key_file, "rb") as f:
                    salt = f.read(16)
                    key = self.key_manager.derive_key_from_password(password, salt)
            else:
                key = Path(key_file).read_bytes()

            output_file = Path(input_file).with_suffix(".enc")
            self.encrypt_progress["value"] = 0
            self.update()
            self.encryptor.encrypt_file(Path(input_file), output_file, key)
            self.encrypt_progress["value"] = 100

            self.logger.log_operation("Encryption", Path(input_file), "SUCCESS")
            self._show_status(f"File encrypted: {output_file}")
            
        except Exception as e:
            self.logger.log_operation("Encryption", Path(input_file), f"FAILED: {str(e)}")
            self._show_status(f"Encryption failed: {str(e)}", False)

    def _perform_decryption(self):
        try:
            input_file = self.decrypt_file_entry.get()
            key_file = self.decrypt_key_entry.get()
            password = self.decrypt_password_entry.get()
            
            if not input_file or not key_file:
                self._show_status("Please select both file and key!", False)
                return

            if password:
                with open(key_file, "rb") as f:
                    salt = f.read(16)
                    key = self.key_manager.derive_key_from_password(password, salt)
            else:
                key = Path(key_file).read_bytes()

            output_file = Path(input_file).with_suffix("")
            self.decrypt_progress["value"] = 0
            self.update()
            self.encryptor.decrypt_file(Path(input_file), output_file, key)
            self.decrypt_progress["value"] = 100

            self.logger.log_operation("Decryption", Path(input_file), "SUCCESS")
            self._show_status(f"File decrypted: {output_file}")
            
        except InvalidTag:
            self.logger.log_operation("Decryption", Path(input_file), "FAILED: Tampered ciphertext")
            self._show_status("Tampered ciphertext detected", False)
        except Exception as e:
            self.logger.log_operation("Decryption", Path(input_file), f"FAILED: {str(e)}")
            self._show_status(f"Decryption failed: {str(e)}", False)

    def _setup_validation(self):
        pass  # Add input validation logic if needed

if __name__ == "__main__":
    CryptoGUI().mainloop()