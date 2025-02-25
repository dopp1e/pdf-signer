import os
from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV
import hashlib
import time

def generate_key():
    key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
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

    print(private_key)
    print(public_key)

    aes_key = hashlib.sha256(b"2137").digest()
    aes = AESGCMSIV(aes_key)
    nonce = os.urandom(12)
    encrypted = aes.encrypt(nonce, data=private_key, associated_data=None)
    print(encrypted)
    decrypted = aes.decrypt(nonce, data=encrypted, associated_data= None)
    print(decrypted)
    # print(aes_key)

