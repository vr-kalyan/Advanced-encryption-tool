import sys
import os
import logging
from datetime import datetime
from PyQt5.QtWidgets import (
    QApplication, QWidget, QPushButton, QVBoxLayout, QFileDialog,
    QLineEdit, QLabel, QMessageBox, QComboBox, QHBoxLayout, QSpacerItem, QSizePolicy
)
from PyQt5.QtGui import QFont, QIcon
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# --- LOGGING & AUDIT SETUP ---
LOG_FILE = "encryption_audit.log"
logging.basicConfig(
    filename=LOG_FILE, level=logging.INFO,
    format='%(asctime)s %(levelname)s | %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

def audit_log(action, filename, algo, status, reason):
    log_msg = (
        f"Action='{action}', File='{filename}', Algorithm='{algo}', Status='{status}'"
        f"{', Reason=' + reason if reason else ''}"
    )
    if status == "SUCCESS":
        logging.info(log_msg)
    else:
        logging.error(log_msg)

def derive_key(password: str, salt: bytes, key_len: int) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=key_len,
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_file(file_path, password, key_size):
    try:
        with open(file_path, 'rb') as f:
            plaintext = f.read()
        salt = os.urandom(16)
        key = derive_key(password, salt, key_size // 8)
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padding_len = 16 - (len(plaintext) % 16)
        plaintext_padded = plaintext + bytes([padding_len] * padding_len)
        ciphertext = encryptor.update(plaintext_padded) + encryptor.finalize()
        enc_file_path = file_path + ".enc"
        with open(enc_file_path, 'wb') as f:
            f.write(salt + iv + ciphertext)
        audit_log("ENCRYPT", os.path.basename(file_path), f"AES-{key_size}", "SUCCESS", None)
        return enc_file_path, None
    except Exception as e:
        audit_log("ENCRYPT", os.path.basename(file_path), f"AES-{key_size}", "FAILURE", str(e))
        return None, f"Encryption failed: {str(e)}"

def decrypt_file(enc_file_path, password, key_size):
    try:
        with open(enc_file_path, 'rb') as f:
            data = f.read()
        if len(data) < 32:
            audit_log("DECRYPT", os.path.basename(enc_file_path), f"AES-{key_size}", "FAILURE", "file too short or invalid")
            return None, "File too short or not a valid encrypted file."
        salt, iv = data[:16], data[16:32]
        ciphertext = data[32:]
        key = derive_key(password, salt, key_size // 8)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext_padded = decryptor.update(ciphertext) + decryptor.finalize()
        padding_len = plaintext_padded[-1]
        if padding_len < 1 or padding_len > 16:
            audit_log("DECRYPT", os.path.basename(enc_file_path), f"AES-{key_size}", "FAILURE", "incorrect password or corrupted file")
            return None, "Incorrect password or corrupted file."
        plaintext = plaintext_padded[:-padding_len]
        dec_file_path = enc_file_path.replace(".enc", ".dec")
        with open(dec_file_path, 'wb') as f:
            f.write(plaintext)
        audit_log("DECRYPT", os.path.basename(enc_file_path), f"AES-{key_size}", "SUCCESS", None)
        return dec_file_path, None
    except Exception as e:
        audit_log("DECRYPT", os.path.basename(enc_file_path), f"AES-{key_size}", "FAILURE", str(e))
        return None, f"Decryption failed: {str(e)}"

class ModernEncryptorApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("🔒 Advanced Encryption Tool")
        self.setGeometry(250, 100, 480, 330)
        self.setStyleSheet("""
            QWidget {
                background-color: #181b21;
                color: #f2f2f2;
                font-family: 'Segoe UI', Arial, sans-serif;
                font-size: 15px;
            }
            QLabel {
                font-weight: bold;
            }
            QLineEdit {
                border: 1.5px solid #5099ea;
                border-radius: 6px;
                padding: 6px;
                font-size: 15px;
                background-color: #24262c;
                color: #e8e8e8;
            }
            QPushButton {
                background-color: #5099ea;
                color: white;
                font-weight: bold;
                border-radius: 8px;
                padding: 10px 0px;
                font-size: 15px;
            }
            QPushButton:hover {
                background-color: #3472b3;
            }
            QComboBox {
                background-color: #24262c;
                color: #f2f2f2;
                border: 1.5px solid #5099ea;
                border-radius: 6px;
                padding: 6px;
            }
        """)

        font_header = QFont("Segoe UI", 18, QFont.Bold)
        font_subheader = QFont("Segoe UI", 10, QFont.Bold)
        layout_main = QVBoxLayout()

        layout_main.addSpacerItem(QSpacerItem(0, 12, QSizePolicy.Minimum, QSizePolicy.Fixed))

        lbl_title = QLabel("🔒 Advanced File Encryption")
        lbl_title.setFont(font_header)
        lbl_title.setStyleSheet("color: #5099ea; margin-bottom: 18px; margin-top: 6px;")
        layout_main.addWidget(lbl_title)

        lbl_file = QLabel("Selected File:")
        lbl_file.setFont(font_subheader)
        layout_main.addWidget(lbl_file)

        self.lbl_file_name = QLabel("None")
        layout_main.addWidget(self.lbl_file_name)

        btn_select = QPushButton("Choose File")
        btn_select.setIcon(QIcon.fromTheme("document-open"))
        btn_select.clicked.connect(self.select_file)
        layout_main.addWidget(btn_select)

        layout_main.addSpacerItem(QSpacerItem(0, 8, QSizePolicy.Minimum, QSizePolicy.Fixed))

        hbox_algo = QHBoxLayout()
        lbl_algo = QLabel("Encryption Algorithm:")
        self.algo_combo = QComboBox()
        self.algo_combo.addItems(["AES-128", "AES-192", "AES-256"])
        hbox_algo.addWidget(lbl_algo)
        hbox_algo.addWidget(self.algo_combo)
        layout_main.addLayout(hbox_algo)

        layout_main.addSpacerItem(QSpacerItem(0, 6, QSizePolicy.Minimum, QSizePolicy.Fixed))

        lbl_pass = QLabel("Password:")
        layout_main.addWidget(lbl_pass)

        self.pass_input = QLineEdit()
        self.pass_input.setEchoMode(QLineEdit.Password)
        self.pass_input.setPlaceholderText("Enter password")
        layout_main.addWidget(self.pass_input)

        hbox_buttons = QHBoxLayout()
        self.btn_encrypt = QPushButton("Encrypt")
        self.btn_encrypt.setIcon(QIcon.fromTheme("lock"))
        self.btn_decrypt = QPushButton("Decrypt")
        self.btn_decrypt.setIcon(QIcon.fromTheme("unlock"))
        self.btn_encrypt.clicked.connect(self.encrypt_file_action)
        self.btn_decrypt.clicked.connect(self.decrypt_file_action)
        hbox_buttons.addWidget(self.btn_encrypt)
        hbox_buttons.addWidget(self.btn_decrypt)
        layout_main.addLayout(hbox_buttons)

        layout_main.addSpacerItem(QSpacerItem(0, 10, QSizePolicy.Minimum, QSizePolicy.Fixed))

        self.lbl_status = QLabel("")
        self.lbl_status.setStyleSheet("color: #e67e22; font-size: 13px; font-weight: bold;")
        layout_main.addWidget(self.lbl_status)

        self.setLayout(layout_main)

    def select_file(self):
        file, _ = QFileDialog.getOpenFileName(self, "Select File")
        if file:
            self.lbl_file_name.setText(f"{os.path.basename(file)}")
            self.file_path = file

    def get_key_size(self):
        sel = self.algo_combo.currentText()
        return {"AES-128": 128, "AES-192": 192, "AES-256": 256}[sel]

    def encrypt_file_action(self):
        if not hasattr(self, "file_path") or not self.pass_input.text():
            QMessageBox.warning(self, "Error", "Select a file and enter a password.")
            return
        key_size = self.get_key_size()
        out, err = encrypt_file(self.file_path, self.pass_input.text(), key_size)
        if out:
            QMessageBox.information(self, "Success", f"File encrypted:\n{out}")
            self.lbl_status.setText("Encryption successful.")
        else:
            QMessageBox.critical(self, "Failure", err)
            self.lbl_status.setText(f"Encrypt Failed: {err}")

    def decrypt_file_action(self):
        if not hasattr(self, "file_path") or not self.pass_input.text():
            QMessageBox.warning(self, "Error", "Select a file and enter a password.")
            return
        if not self.file_path.endswith(".enc"):
            QMessageBox.warning(self, "Error", "Select a .enc file to decrypt.")
            return
        key_size = self.get_key_size()
        out, err = decrypt_file(self.file_path, self.pass_input.text(), key_size)
        if out:
            QMessageBox.information(self, "Success", f"File decrypted:\n{out}")
            self.lbl_status.setText("Decryption successful.")
        else:
            QMessageBox.critical(self, "Failure", err)
            self.lbl_status.setText(f"Decrypt Failed: {err}")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = ModernEncryptorApp()
    window.show()
    sys.exit(app.exec_())