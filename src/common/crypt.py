import os
from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV
import hashlib

class Crypt:
    def __init__():
        pass

    def generate_key(self, public_exponent: int, key_size: int, aes_key: str) -> tuple[bytes, bytes]:
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