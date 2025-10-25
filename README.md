# 🌐 m223rx – NorthVault Password Manager

![NorthVaultPy Screenshot](/resources/screenshots/home.png)

---

## 🚀 Features  

- **Secure Password Vault**  
  Encrypts and stores passwords in a local vault (`vault.json.enc`) using strong encryption.  

- **Master Password Authentication**  
  Only the user with the master password can access saved credentials.  

- **Generate Strong Passwords**  
  Generate secure, random passwords of customizable length for any service.  

- **Save, Update & Delete Credentials**  
  Easily manage service credentials with unique IDs for each entry.  

- **Encrypted Local Storage**  
  Ensures passwords are safely stored on your machine without sending data online.  

- **Cross-Platform CLI Interface**  
  Works seamlessly on Windows, Linux, and macOS terminals with clear, intuitive prompts.  

- **Config File for User Details**  
  Saves username, email, theme preference, and vault path in a `config.json` file.  

- **Clear Terminal Interface**  
  Clean, distraction-free CLI experience with cross-platform screen clearing.  

---

## 🛠 Tech Stack

- **Language:**  
  - [Python 3](https://www.python.org/) – program logic, file handling, encryption  

- **Libraries:**  
  - [PyCryptodome](https://pycryptodome.readthedocs.io/) – encryption & decryption  
  - [uuid](https://docs.python.org/3/library/uuid.html) – unique IDs for credentials  

- **Deployment:**  
  - Run locally on any system with Python 3 installed  
  - CLI-based, no external hosting required  

---

## ⚡ Usage

1. **Clone the repository:**

   ```bash
   git clone https://github.com/m223rx/NorthVaultPy.git
   cd NorthVault
   ```

2. **Create a virtual environment (optional but recommended)**  
    python3 -m venv venv
    source venv/bin/activate   # Linux/macOS
    venv\Scripts\activate      # Windows

3. **Install dependencies**  
   pip install -r requirements.txt

4. **Run NorthVaultPy**  
    python main.py  

5. **Follow the prompts**  
    If first time: create a new user with username, email, and master password.

    Use the master password to authenticate.

    Choose from the CLI menu to view, add, or delete saved passwords, or generate new strong passwords.

---

## 🎨 Customization

- Change themes or preferences in config.json. 
- Adjust password generation rules in utils/password_gen.py. 
- Modify CLI interface or add new commands in main.py.

---

## 💡 Future Enhancements

- Add a PyQt5 GUI with splash screen and cinematic transitions.
- Multi-user support with separate encrypted vaults per user.
- Export/backup vault securely.
- Password strength analysis and password reuse alerts.
- Dark/Light mode or customizable CLI themes.

---

## 👨‍💻 Developer

m223rx – 2025  

© 2025 m223rx. All rights reserved.
