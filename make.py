import base64
import datetime
import json
import os

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

def encrypt_data(password: str, expiry_days: int) -> str:
    salt = os.urandom(16)
    key = create_key(password, salt)
    fernet = Fernet(key)
    expiry_date = datetime.datetime.now() + datetime.timedelta(days=expiry_days)
    data_with_expiry = json.dumps({"expiry_date": expiry_date.isoformat()})
    encrypted_data = fernet.encrypt(data_with_expiry.encode())
    return base64.urlsafe_b64encode(salt + encrypted_data).decode()

# Input dari pengguna
expiry_days = int(input("Masukkan jumlah hari untuk kadaluarsa: "))
password = input("Masukkan password: ")


# Enkripsi data
encrypted = encrypt_data(password, expiry_days)
print(f"Data terenkripsi: {encrypted}")