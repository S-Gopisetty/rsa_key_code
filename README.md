# 🔑 RSA Key Code

A Python utility for **generating and validating RSA (and other asymmetric) key pairs** using the [`cryptography`](https://cryptography.io/en/latest/) library.  

This project provides:  
- Secure RSA key-pair generation.  
- Option to encrypt private keys with a password.  
- Display of key metadata (size, filenames, password protection status).  
- Validation of existing keys to check if they require a password.  

---

## 📂 Project Structure

```
rsa_key_code/
├── generateKeys.py     # Script to generate new RSA key pairs
├── validateKeys.py     # Script to validate existing keys
├── requirements.txt    # Python dependencies
└── README.md           # Project documentation
```

---

## ⚙️ Installation

1. Clone this repository:
   ```bash
   git clone https://github.com/S-Gopisetty/rsa_key_code.git
   cd rsa_key_code
   ```

2. Create a virtual environment (recommended):
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate   # Linux/Mac
   .venv\Scripts\activate      # Windows
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

---

## 🛠️ Usage

### 🔹 Generate Keys
Run the generator script:

```bash
python generateKeys.py
```

You will be prompted for:  
- **Encryption (yes/no)** → Whether to protect the private key with a password.  
- **Password** (if encryption chosen).  
- Keys will be saved in a folder named after the key file.  

Example:
```
Do you want to encrypt the private key? (y/n): y
Enter password: ********
Keys generated successfully!
Saved in: ./my_private_key/
```

---

### 🔹 Validate Keys
To check if a key is valid and whether it requires a password:

```bash
python validateKeys.py
```

You will be prompted for:  
- **Folder name** containing the keys.  
- **Key filenames** to validate.  
- Password (if required).  

Output includes:  
- Key type (RSA, DSA, EC, etc.)  
- Key size  
- Whether password is required  

---

## 📦 Requirements

All dependencies are listed in `requirements.txt`:

```
cryptography>=41.0.0
```

Python **3.9+** is recommended.

---

## 📌 Roadmap

- [ ] Add support for exporting keys in DER format.  
- [ ] Add command-line arguments (no prompts).  
- [ ] Add unit tests with `pytest`.  
- [ ] Extend to support signing/verification.  

---

## 🤝 Contributing

1. Fork this repo.  
2. Create a feature branch (`git checkout -b feature-name`).  
3. Commit changes (`git commit -m "Add feature"`).  
4. Push to your branch (`git push origin feature-name`).  
5. Open a Pull Request.  

---
