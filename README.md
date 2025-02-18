
# Password Manager

## Overview
This project is a **Password Manager** built using Python and the `cryptography` library. It allows users to securely store, encrypt, and retrieve passwords for different accounts. The tool uses a master password to encrypt and decrypt stored credentials, ensuring that sensitive data remains protected.

## Features
- **Secure Encryption**: Uses the `Fernet` encryption from the `cryptography` library for secure password storage.
- **Salted Key Derivation**: Implements a salt file (`salt.key`) to enhance security by generating unique encryption keys.
- **Password Storage**: Stores encrypted passwords in a structured file (`passwords.txt`).
- **User-Friendly Interface**: Allows users to add new passwords or view existing ones through a simple command-line interface.

## Prerequisites
- Python 3.x installed on your system.
- Install the required library using:
  ```
  pip install cryptography
  ```

## How It Works
1. **Initialization**:
   - A master password is used to derive an encryption key using PBKDF2HMAC (Password-Based Key Derivation Function).
   - A salt file (`salt.key`) is created (or reused if it already exists) to ensure unique key derivation.

2. **Adding Passwords**:
   - Users can input account names and passwords.
   - Passwords are encrypted and stored in the `passwords.txt` file in the format:  
     ```
     account_name|encrypted_password
     ```

3. **Viewing Passwords**:
   - Encrypted passwords are decrypted using the master password and displayed along with their respective account names.

## File Structure
- **`fernet passwordmanager.py`**: Main Python script implementing the password manager with encryption.
- **`salt.key`**: Stores the random salt value for key derivation.
- **`passwords.txt`**: Stores encrypted account credentials.
- **Other Python files**: Additional scripts for experimentation or modular functionality.

## Usage Instructions
1. Run the main script:
   ```
   python fernet_passwordmanager.py
   ```
2. Enter the master password when prompted.
3. Choose from the following options:
   - `view`: View stored account credentials.
   - `add`: Add a new account and password.
   - `q`: Quit the program.

### Example Workflow
```
Enter the master password: my_secure_master_password

Would you like to add a new password or view existing ones (view, add), press q to quit? add
Account Name: Gmail
Password: my_gmail_password

Would you like to add a new password or view existing ones (view, add), press q to quit? view
Account: Gmail | Password: my_gmail_password

Would you like to add a new password or view existing ones (view, add), press q to quit? q
```

## Security Notes
- The master password is never stored; it is only used to derive the encryption key during runtime.
- The salt file (`salt.key`) is critical for decryption. Do not delete or lose this file, as it will render stored passwords unrecoverable.
- Ensure that `passwords.txt` and `salt.key` are stored securely and not shared with unauthorized individuals.

## Dependencies
This project uses the following Python libraries:
- `os`: For file handling and generating random bytes for salt.
- `base64`: Encoding derived keys into a safe format.
- `cryptography`: For implementing encryption using Fernet and PBKDF2HMAC.

Install dependencies with:
```
pip install cryptography
```

## Future Improvements
- Add a graphical user interface (GUI) for better usability.
- Implement password strength validation before storing passwords.
- Add support for exporting/importing encrypted data.

## Author
This project was developed on January 21, 2025, as part of a learning exercise in cryptography and secure programming practices.

Enjoy using your secure Password Manager!
