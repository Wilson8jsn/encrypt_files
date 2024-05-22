from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import base64
import os
import getpass


def derive_key_from_password(password, salt=None):
    if not salt:
        salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key, salt


def encrypt_file(file_name, password):
    key, salt = derive_key_from_password(password)
    fernet = Fernet(key)

    with open(file_name, "rb") as file:
        original = file.read()

    encrypted = fernet.encrypt(original)

    with open(file_name, "wb") as encrypted_file:
        encrypted_file.write(salt + encrypted)


def decrypt_file(file_name, password):
    with open(file_name, "rb") as encrypted_file:
        data = encrypted_file.read()
    
    salt = data[:16]
    encrypted = data[16:]
    
    key, _ = derive_key_from_password(password, salt)
    fernet = Fernet(key)
    decrypted = fernet.decrypt(encrypted)

    with open(file_name, "wb") as decrypted_file:
        decrypted_file.write(decrypted)

if __name__ == "__main__":
    import sys

    if len(sys.argv) != 3:
        print("Uso: python encrypt_files.py <encrypt/decrypt> <file_path>")
        sys.exit(1)

    option = sys.argv[1]
    file_path = sys.argv[2]

    password = getpass.getpass(prompt='Introduce la contraseña: ')

    if option == "encrypt":
        encrypt_file(file_path, password)
        print(f"Archivo {file_path} encriptado exitosamente.")
    elif option == "decrypt":
        decrypt_file(file_path, password)
        print(f"Archivo {file_path} desencriptado exitosamente.")
    else:
        print("Opción no válida. Usa 'encrypt' o 'decrypt'.")
