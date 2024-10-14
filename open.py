import base64

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def create_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def decrypt_data(encrypted_data: str, password: str) -> str:
    decoded = base64.urlsafe_b64decode(encrypted_data)
    salt = decoded[:16]
    encrypted = decoded[16:]
    key = create_key(password, salt)
    fernet = Fernet(key)
    return fernet.decrypt(encrypted).decode()

# Input dari pengguna
encrypted_data = input("Masukkan data terenkripsi: ")
password = input("Masukkan password: ")

# Dekripsi data
try:
    decrypted = decrypt_data(encrypted_data, password)
    print(f"Data terdekripsi: {decrypted}")
except Exception as e:
    print(f"Gagal mendekripsi data: {e}")