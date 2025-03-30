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
    
def is_divisible(divisee: int, divisor: int):
    return divisee % divisor == 0

def generate_key(public_exponent: int, key_size: int, password: str):
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

    aes_key = hashlib.sha256(password.encode()).digest()
    aes = AESGCMSIV(aes_key)
    nonce = os.urandom(12)
    return nonce, aes.encrypt(nonce, data=private_key, associated_data=None), public_key

def make_location(watch_folder: str, pendrive_name: str):
    return watch_folder + QDir.separator() + pendrive_name

def prepare_location(watch_folder: str, pendrive_name: str):
    location = make_location(watch_folder, pendrive_name)
    location_dir = QDir(location)
    if (not location_dir.exists(".pdf-signer")):
        location_dir.mkdir(".pdf-signer")

def make_key_location(watch_folder: str, pendrive_name: str):
    return make_location(watch_folder, pendrive_name) + QDir.separator() + ".pdf-signer"

def build_key_path(location: str, key_name: str):
    return location + QDir.separator() + key_name

def nonce_path(location: str, key_name: str):
    return build_key_path(location, key_name) + QDir.separator() + "nonce"

def private_key_path(location: str, key_name: str):
    return build_key_path(location, key_name) + QDir.separator() + "private_key"

def public_key_path(location: str, key_name: str):
    return build_key_path(location, key_name) + QDir.separator() + "public_key"

def does_key_exist(location: str, key_name: str):
    key_path = build_key_path(location, key_name)
    dir = QDir(key_path)
    return dir.exists()

def make_key(key_size: int, password: str, location: str, key_name: str):
    dir = QDir(location)
    dir.mkdir(key_name)
    nonce, encrypted_private_key, public_key = generate_key(65537, key_size, password)
    
    nonce_file = QFile(nonce_path(location, key_name))
    if (nonce_file.open(QFile.OpenModeFlag.WriteOnly)):
        nonce_file.write(nonce)
        nonce_file.close()

    private_key_file = QFile(private_key_path(location, key_name))
    if (private_key_file.open(QFile.OpenModeFlag.WriteOnly)):
        private_key_file.write(encrypted_private_key)
        private_key_file.close()

    public_key_file = QFile(public_key_path(location, key_name))
    if (public_key_file.open(QFile.OpenModeFlag.WriteOnly)):
        public_key_file.write(public_key)
        public_key_file.close()

    return 0

def load_private_key(password: str, location: str, key_name: str):
    key_path = build_key_path(location, key_name)
    dir = QDir(key_path)
    if not dir.exists():
        return 1
    
    nonce = 0
    nonce_file = QFile(nonce_path(location, key_name))
    if (nonce_file.open(QFile.OpenModeFlag.ReadOnly)):
        nonce = nonce_file.readAll()
        nonce_file.close()

    private_key = 0
    private_key_file = QFile(private_key_path(location, key_name))
    if (private_key_file.open(QFile.OpenModeFlag.ReadOnly)):
        private_key = private_key_file.readAll()
        private_key_file.close()

    aes_key = hashlib.sha256(password.encode()).digest()
    aes = AESGCMSIV(aes_key)

    try:
        private_key = aes.decrypt(nonce, data=private_key, associated_data=None)
    except:
        return False
    
    return True, private_key

def list_keys(location: str):
    dir = QDir(location)
    dir.setFilter(QDir.Filter.Dirs | QDir.Filter.NoDotAndDotDot)
    key_list = dir.entryList()
    return key_list

def delete_key(location: str, key: str):
    path = build_key_path(location, key)
    dir = QDir(path)
    dir.removeRecursively()