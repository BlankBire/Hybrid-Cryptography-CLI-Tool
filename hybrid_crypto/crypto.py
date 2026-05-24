"""Core hybrid encryption/decryption engine — streaming, compressed, versioned.

Binary layout of a .hcrypt file:
  [6 bytes]   Magic + version: b"HCRY\\x01\\x00"
  [1 byte]    Flags: bit 0 = zlib-compressed plaintext chunks
  [4 bytes]   Big-endian encrypted-key length
  [N bytes]   RSA-OAEP encrypted AES-GCM session key  (N == 512 for RSA-4096)
  [12 bytes]  Base nonce

  Repeated until EOF sentinel:
    [4 bytes]   Chunk ciphertext length  (value 0 = end-of-stream)
    [M bytes]   AES-GCM ciphertext + 16-byte auth tag

Per-chunk nonce: base_nonce XOR (chunk_index as big-endian uint32 in last 4 bytes).
This guarantees every chunk uses a unique nonce while keeping the header size fixed.
"""

import os
import struct
import zlib

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"HCRY\x01\x00"      # 4-byte file identifier + major version + minor version
FLAG_COMPRESSED = 0x01

_KEY_LEN_FORMAT = ">I"
_KEY_LEN_SIZE = struct.calcsize(_KEY_LEN_FORMAT)
_CHUNK_LEN_FORMAT = ">I"
_CHUNK_LEN_SIZE = struct.calcsize(_CHUNK_LEN_FORMAT)

AES_KEY_BYTES = 32      # 256-bit session key
NONCE_BYTES = 12        # 96-bit base nonce — recommended for AES-GCM
CHUNK_SIZE = 64 * 1024  # 64 KB per chunk


def _oaep_padding():
    return padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )


def _chunk_nonce(base_nonce: bytes, index: int) -> bytes:
    """Derive a unique per-chunk nonce by XORing the last 4 bytes with the chunk index.

    Supports up to 2^32 chunks (~256 TB at 64 KB/chunk) before nonce collision.
    """
    n = bytearray(base_nonce)
    idx = struct.pack(">I", index)
    n[8] ^= idx[0]
    n[9] ^= idx[1]
    n[10] ^= idx[2]
    n[11] ^= idx[3]
    return bytes(n)


def _iter_file_chunks(fh, chunk_size: int = CHUNK_SIZE):
    while True:
        chunk = fh.read(chunk_size)
        if not chunk:
            return
        yield chunk


def encrypt_file(
    input_path: str,
    output_path: str,
    public_key,
    compress: bool = True,
) -> None:
    """Stream-encrypt *input_path* to *output_path* using the recipient's RSA public key.

    Memory usage is bounded by CHUNK_SIZE regardless of input file size.
    """
    session_key = os.urandom(AES_KEY_BYTES)
    base_nonce = os.urandom(NONCE_BYTES)
    aesgcm = AESGCM(session_key)

    encrypted_session_key = public_key.encrypt(session_key, _oaep_padding())
    flags = FLAG_COMPRESSED if compress else 0x00

    with open(input_path, "rb") as fin, open(output_path, "wb") as fout:
        fout.write(MAGIC)
        fout.write(bytes([flags]))
        fout.write(struct.pack(_KEY_LEN_FORMAT, len(encrypted_session_key)))
        fout.write(encrypted_session_key)
        fout.write(base_nonce)

        for chunk_index, chunk in enumerate(_iter_file_chunks(fin)):
            if compress:
                chunk = zlib.compress(chunk)
            ciphertext = aesgcm.encrypt(_chunk_nonce(base_nonce, chunk_index), chunk, None)
            fout.write(struct.pack(_CHUNK_LEN_FORMAT, len(ciphertext)))
            fout.write(ciphertext)

        fout.write(struct.pack(_CHUNK_LEN_FORMAT, 0))  # EOF sentinel


def decrypt_file(input_path: str, output_path: str, private_key) -> None:
    """Stream-decrypt *input_path* to *output_path* using the recipient's RSA private key.

    Raises:
        ValueError                         — malformed header or unrecognised format.
        cryptography.exceptions.InvalidTag — any chunk has been tampered with.
    """
    with open(input_path, "rb") as fin, open(output_path, "wb") as fout:
        # --- validate magic & version ---
        magic = fin.read(len(MAGIC))
        if magic != MAGIC:
            raise ValueError("Not a valid .hcrypt file (bad magic bytes).")

        flags_byte = fin.read(1)
        if not flags_byte:
            raise ValueError("File is too short: missing flags byte.")
        compressed = bool(flags_byte[0] & FLAG_COMPRESSED)

        # --- parse header ---
        raw_key_len = fin.read(_KEY_LEN_SIZE)
        if len(raw_key_len) < _KEY_LEN_SIZE:
            raise ValueError("File is too short to be a valid .hcrypt archive.")
        (key_len,) = struct.unpack(_KEY_LEN_FORMAT, raw_key_len)

        encrypted_session_key = fin.read(key_len)
        if len(encrypted_session_key) != key_len:
            raise ValueError("Truncated encrypted session key.")

        base_nonce = fin.read(NONCE_BYTES)
        if len(base_nonce) != NONCE_BYTES:
            raise ValueError("Truncated nonce.")

        # --- unwrap session key ---
        session_key = private_key.decrypt(encrypted_session_key, _oaep_padding())
        aesgcm = AESGCM(session_key)

        # --- stream-decrypt chunks ---
        chunk_index = 0
        while True:
            raw_chunk_len = fin.read(_CHUNK_LEN_SIZE)
            if len(raw_chunk_len) < _CHUNK_LEN_SIZE:
                raise ValueError("Unexpected end of file reading chunk header.")
            (chunk_len,) = struct.unpack(_CHUNK_LEN_FORMAT, raw_chunk_len)
            if chunk_len == 0:
                break  # EOF sentinel

            ciphertext = fin.read(chunk_len)
            if len(ciphertext) != chunk_len:
                raise ValueError(f"Truncated chunk {chunk_index}.")

            # AESGCM.decrypt raises InvalidTag automatically on any tampering
            plaintext_chunk = aesgcm.decrypt(
                _chunk_nonce(base_nonce, chunk_index), ciphertext, None
            )
            if compressed:
                plaintext_chunk = zlib.decompress(plaintext_chunk)

            fout.write(plaintext_chunk)
            chunk_index += 1
