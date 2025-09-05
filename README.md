# 🔒 Advanced Encryption Tool

## What is an "Advanced Encryption Tool"?

An **Advanced Encryption Tool** is a robust application designed to keep your files secure through the use of strong cryptographic algorithms. These tools leverage industry-standard encryption (such as AES) to protect sensitive data, ensuring that only those with the proper password or key can decrypt and access the original contents. Such tools are widely used in business, personal privacy, compliance, and anywhere digital data security is essential.

---

## Features

### 🚀 Multiple Encryption Algorithms
- Choose between **AES-128**, **AES-192**, and **AES-256** for file encryption/decryption.
- Flexible algorithm selection enables balancing speed and security according to your needs.

### ⚡ Robust Error Handling
- The tool delivers clear, user-friendly messages for all error conditions (wrong password, corrupted/incompatible files, or invalid operations).
- Prevents accidental overwrites and ensures that only valid actions proceed.

### 🎨 Modern UI Design
- Clean, visually appealing interface using a modern color palette.
- Large buttons, password masking, algorithm selection, dynamic status messages, and responsive layouts for exceptional ease of use.
- Desktop-style application with a professional finish.

![Modern UI Screenshot]

### 📜 Logging & Audit Monitoring
- All actions (encrypt/decrypt) are recorded in a detailed `encryption_audit.log` file.
- Each log entry includes the time, action, file, algorithm selection, outcome, and error (if any).
- This audit trail supports compliance, troubleshooting, and security monitoring.

---

## How the Tool Works

1. **Select File:** Users choose any file to encrypt or decrypt.
2. **Choose Algorithm:** Select preferred encryption strength (AES-128, AES-192, or AES-256).
3. **Enter Password:** This password derives a secure key for encryption/decryption. The application never stores passwords or keys.
4. **Encrypt/Decrypt:** One-click operation performs the chosen action with instant feedback and a log entry.

### Result Example

Here’s how your files look before and after encryption/decryption:

![File Workflow Example]

- The original file (left)
- After encryption, an `.enc` version appears (middle)
- After decryption, a `.dec` version is produced (right)
- Encrypted files are unreadable without the correct password and algorithm

---

## Getting Started

1. **Requirements:**  
   - Python 3.x  
   - `pyqt5`, `cryptography` libraries (`pip install pyqt5 cryptography`)
2. **Run:**  
   - Save the project script and execute with `python script_name.py`

3. **Logs:**  
   - Review `encryption_audit.log` in the project directory for a record of every action.

---

## License

This project is open for educational and personal use. For business or compliance scenarios, consult local data protection laws and best practices for encryption and log management.
