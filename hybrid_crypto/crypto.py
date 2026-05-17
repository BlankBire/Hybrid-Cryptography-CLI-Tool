"""Core hybrid encryption/decryption engine.

Binary layout of a .hcrypt file:
  [4 bytes big-endian]  — length of the RSA-encrypted session key
  [N bytes]             — RSA-OAEP encrypted AES-GCM session key  (N == 512 for RSA-4096)
  [12 bytes]            — AES-GCM nonce
  [variable]            — AES-GCM ciphertext + 16-byte authentication tag
"""

import os
import struct

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Struct format: 4-byte big-endian unsigned int
_KEY_LEN_FORMAT = ">I"
_KEY_LEN_SIZE = struct.calcsize(_KEY_LEN_FORMAT)

AES_KEY_BYTES = 32   # 256-bit session key
NONCE_BYTES = 12     # 96-bit nonce — recommended for AES-GCM


def _oaep_padding():
    return padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )


def encrypt_file(input_path: str, output_path: str, public_key) -> None:
    """Encrypt *input_path* to *output_path* using the recipient's RSA public key."""
    session_key = os.urandom(AES_KEY_BYTES)
    nonce = os.urandom(NONCE_BYTES)

    plaintext = open(input_path, "rb").read()
    ciphertext = AESGCM(session_key).encrypt(nonce, plaintext, None)

    encrypted_session_key = public_key.encrypt(session_key, _oaep_padding())

    with open(output_path, "wb") as f:
        f.write(struct.pack(_KEY_LEN_FORMAT, len(encrypted_session_key)))
        f.write(encrypted_session_key)
        f.write(nonce)
        f.write(ciphertext)


def decrypt_file(input_path: str, output_path: str, private_key) -> None:
    """Decrypt *input_path* to *output_path* using the recipient's RSA private key.

    Raises:
        cryptography.exceptions.InvalidTag — if the ciphertext has been tampered with.
        ValueError                         — if the file header is malformed.
    """
    with open(input_path, "rb") as f:
        raw_key_len_bytes = f.read(_KEY_LEN_SIZE)
        if len(raw_key_len_bytes) < _KEY_LEN_SIZE:
            raise ValueError("File is too short to be a valid .hcrypt archive.")

        (key_len,) = struct.unpack(_KEY_LEN_FORMAT, raw_key_len_bytes)

        encrypted_session_key = f.read(key_len)
        if len(encrypted_session_key) != key_len:
            raise ValueError("Truncated encrypted session key.")

        nonce = f.read(NONCE_BYTES)
        if len(nonce) != NONCE_BYTES:
            raise ValueError("Truncated nonce.")

        ciphertext = f.read()

    session_key = private_key.decrypt(encrypted_session_key, _oaep_padding())

    # AESGCM.decrypt raises InvalidTag automatically if authentication fails
    plaintext = AESGCM(session_key).decrypt(nonce, ciphertext, None)

    open(output_path, "wb").write(plaintext)
