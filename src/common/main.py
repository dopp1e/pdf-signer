import os
from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV
import hashlib
import time
from PyQt6.QtCore import QFile, QDir

def represents_int(a: str):
    try:
        return int(a)
    except ValueError:
        return False

def generate_key(public_exponent: int, key_size: int, password: str, location: str):
    key = rsa.generate_private_key(
            public_exponent,
            key_size
        )

    private_key = key.private_bytes(
            crypto_serialization.Encoding.PEM,
            crypto_serialization.PrivateFormat.PKCS8,
            crypto_serialization.NoEncryption()
        )

    public_key = key.public_key().public_bytes(
            crypto_serialization.Encoding.PEM,
            crypto_serialization.PublicFormat.PKCS1
            )

    #print(private_key)
    #print(public_key)

    aes_key = hashlib.sha256(password.encode()).digest()
    aes = AESGCMSIV(aes_key)
    nonce = os.urandom(12)
    return nonce, aes.encrypt(nonce, data=private_key, associated_data=None)

def build_key_path(location: str, key_name: str):
    return location + QDir.separator() + key_name

def nonce_path(location: str, key_name: str):
    return build_key_path(location, key_name) + QDir.separator() + "nonce"

def key_path(location: str, key_name: str):
    return build_key_path(location, key_name) + QDir.separator() + "key"

def make_key(public_exponent: int, key_size: int, password: str, location: str):
    dir = QDir(location)
    if dir.exists():
        return 1

    dir.mkdir(location)
    nonce, encrypted = generate_key(public_exponent, key_size, password, location)
    
    nonce_file = QFile(location + QDir.separator() + "nonce")
    if (nonce_file.open(QFile.OpenModeFlag.WriteOnly)):
        nonce_file.write(nonce)
        nonce_file.close()

    key_file = QFile(location + QDir.separator() + "key")
    if (key_file.open(QFile.OpenModeFlag.WriteOnly)):
        key_file.write(encrypted)
        key_file.close()

make_key(65537, 4096, "pass", "/home/doppie/test")