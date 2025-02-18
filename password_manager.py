#here we will use cryptography library to encrypt and decrypt the password
#.encode turns the string into bytes
#A salt file stores a random value (salt) that is crucial for secure password hashing and encryption
#The password file stores the encrypted account credentials in a structured format
#use pip install cryptography to install the library


#basics of cryptography(from documentation)
"""
password = b"password"  # Master password in bytes
salt = os.urandom(16)   # Generates 16 random bytes as salt

# Create a key derivation function
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),    # Uses SHA256 hashing
    length=32,                    # Produces a 32-byte key
    salt=salt,                    # Adds the random salt
    iterations=1_000_000,         # Number of iterations for extra security
)

# Generate the encryption key
key = base64.urlsafe_b64encode(kdf.derive(password))

# Create Fernet cipher object
f = Fernet(key)

# Example encryption/decryption
token = f.encrypt(b"Secret message!")  # Encrypts a message
f.decrypt(token)                       # Decrypts back to original message"""




import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class PasswordManager:
    def __init__(self):
        self.key = None
        self.fer = None
        self.salt_file = "salt.key"
        self.password_file = "passwords.txt"

    def initialize(self, master_password):
        if not os.path.exists(self.salt_file):
            salt = os.urandom(16)
            with open(self.salt_file, "wb") as salt_file:
                salt_file.write(salt)
        else:
            with open(self.salt_file, "rb") as salt_file:
                salt = salt_file.read()

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100_000,
        )
        
        key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
        self.fer = Fernet(key)

    def view(self):
        if not os.path.exists(self.password_file):
            print("No passwords stored yet.")
            return
            
        with open(self.password_file, 'r') as f:
            for line in f.readlines():
                data = line.rstrip()
                user, passw = data.split("|")
                try:
                    decrypted_pass = self.fer.decrypt(passw.encode()).decode()
                    print("Account:", user, "| Password:", decrypted_pass)
                except:
                    print("Error decrypting password for", user)

    def add(self):
        account = input('Account Name: ')
        password = input("Password: ")

        with open(self.password_file, 'a') as f:
            encrypted_pass = self.fer.encrypt(password.encode()).decode()
            f.write(f"{account}|{encrypted_pass}\n")

def main():
    pm = PasswordManager()
    master_pwd = input("Enter the master password: ")
    pm.initialize(master_pwd)

    while True:
        mode = input(
            "Would you like to add a new password or view existing ones (view, add), press q to quit? "
        ).lower()
        
        if mode == "q":
            break
        elif mode == "view":
            pm.view()
        elif mode == "add":
            pm.add()
        else:
            print("Invalid mode.")

if __name__ == "__main__":
    main()
