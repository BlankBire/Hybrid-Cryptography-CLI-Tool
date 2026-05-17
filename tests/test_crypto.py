"""Tests for the hybrid cryptography engine.

Test categories:
  1. Round-trip: encrypt → decrypt produces original plaintext.
  2. Key isolation: wrong private key cannot decrypt.
  3. Tamper defense: any modification to the ciphertext raises InvalidTag.
  4. Header corruption: malformed header raises ValueError.
"""

import os
import struct
import tempfile

import pytest
from cryptography.exceptions import InvalidTag

from hybrid_crypto.crypto import NONCE_BYTES, _KEY_LEN_FORMAT, _KEY_LEN_SIZE, decrypt_file, encrypt_file
from hybrid_crypto.keys import generate_rsa_keypair


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def key_pair():
    private_key, public_key = generate_rsa_keypair(key_size=2048)  # 2048 for speed in tests
    return private_key, public_key


@pytest.fixture(scope="module")
def wrong_key_pair():
    private_key, public_key = generate_rsa_keypair(key_size=2048)
    return private_key, public_key


@pytest.fixture()
def tmp(tmp_path):
    """Return a helper that creates a temp file with given content."""
    def _make(name: str, content: bytes = b"") -> str:
        path = tmp_path / name
        path.write_bytes(content)
        return str(path)
    return _make, tmp_path


# ---------------------------------------------------------------------------
# 1. Round-trip tests
# ---------------------------------------------------------------------------

class TestRoundTrip:
    def test_small_plaintext(self, key_pair, tmp):
        mk, td = tmp
        private_key, public_key = key_pair
        src = mk("plain.txt", b"Hello, Hybrid Crypto!")
        enc = str(td / "plain.txt.hcrypt")
        dec = str(td / "plain_decrypted.txt")

        encrypt_file(src, enc, public_key)
        decrypt_file(enc, dec, private_key)

        assert open(dec, "rb").read() == b"Hello, Hybrid Crypto!"

    def test_empty_file(self, key_pair, tmp):
        mk, td = tmp
        private_key, public_key = key_pair
        src = mk("empty.bin", b"")
        enc = str(td / "empty.hcrypt")
        dec = str(td / "empty_dec.bin")

        encrypt_file(src, enc, public_key)
        decrypt_file(enc, dec, private_key)

        assert open(dec, "rb").read() == b""

    def test_binary_content(self, key_pair, tmp):
        private_key, public_key = key_pair
        mk, td = tmp
        payload = os.urandom(64 * 1024)  # 64 KB of random bytes
        src = mk("random.bin", payload)
        enc = str(td / "random.hcrypt")
        dec = str(td / "random_dec.bin")

        encrypt_file(src, enc, public_key)
        decrypt_file(enc, dec, private_key)

        assert open(dec, "rb").read() == payload

    def test_each_encryption_produces_different_ciphertext(self, key_pair, tmp):
        """Session key and nonce are random; two encryptions of same plaintext differ."""
        private_key, public_key = key_pair
        mk, td = tmp
        src = mk("msg.txt", b"Same plaintext")
        enc1 = str(td / "msg1.hcrypt")
        enc2 = str(td / "msg2.hcrypt")

        encrypt_file(src, enc1, public_key)
        encrypt_file(src, enc2, public_key)

        assert open(enc1, "rb").read() != open(enc2, "rb").read()


# ---------------------------------------------------------------------------
# 2. Key isolation
# ---------------------------------------------------------------------------

class TestKeyIsolation:
    def test_wrong_private_key_fails(self, key_pair, wrong_key_pair, tmp):
        private_key, public_key = key_pair
        wrong_private_key, _ = wrong_key_pair
        mk, td = tmp
        src = mk("secret.txt", b"Top secret data")
        enc = str(td / "secret.hcrypt")
        dec = str(td / "secret_wrong_dec.txt")

        encrypt_file(src, enc, public_key)

        with pytest.raises(Exception):  # ValueError from RSA OAEP decryption
            decrypt_file(enc, dec, wrong_private_key)


# ---------------------------------------------------------------------------
# 3. Tamper defense — the "attacker" test
# ---------------------------------------------------------------------------

class TestTamperDefense:
    """Simulate an attacker modifying the .hcrypt file byte by byte."""

    def _encrypt_sample(self, key_pair, tmp):
        private_key, public_key = key_pair
        mk, td = tmp
        src = mk("tamper_src.txt", b"Sensitive document content that must not be tampered.")
        enc = str(td / "tamper.hcrypt")
        encrypt_file(src, enc, public_key)
        return enc

    def test_flip_single_ciphertext_bit(self, key_pair, tmp):
        """Flipping one bit in the ciphertext body must raise InvalidTag."""
        private_key, public_key = key_pair
        enc = self._encrypt_sample(key_pair, tmp)
        mk, td = tmp
        dec = str(td / "tamper_flip_dec.txt")

        raw = bytearray(open(enc, "rb").read())

        # Calculate start of ciphertext region
        (key_len,) = struct.unpack(_KEY_LEN_FORMAT, raw[:_KEY_LEN_SIZE])
        ciphertext_start = _KEY_LEN_SIZE + key_len + NONCE_BYTES

        # Flip the first byte of ciphertext
        raw[ciphertext_start] ^= 0xFF
        tampered_path = str(td / "tampered_flip.hcrypt")
        open(tampered_path, "wb").write(raw)

        with pytest.raises(InvalidTag):
            decrypt_file(tampered_path, dec, private_key)

    def test_append_garbage_bytes(self, key_pair, tmp):
        """Appending bytes to ciphertext must raise InvalidTag."""
        private_key, public_key = key_pair
        enc = self._encrypt_sample(key_pair, tmp)
        mk, td = tmp
        dec = str(td / "tamper_append_dec.txt")

        raw = open(enc, "rb").read() + b"\xde\xad\xbe\xef"
        tampered_path = str(td / "tampered_append.hcrypt")
        open(tampered_path, "wb").write(raw)

        with pytest.raises(InvalidTag):
            decrypt_file(tampered_path, dec, private_key)

    def test_truncate_auth_tag(self, key_pair, tmp):
        """Removing the last 16 bytes (auth tag) must raise InvalidTag."""
        private_key, public_key = key_pair
        enc = self._encrypt_sample(key_pair, tmp)
        mk, td = tmp
        dec = str(td / "tamper_trunc_dec.txt")

        raw = open(enc, "rb").read()[:-16]  # strip the 16-byte GCM tag
        tampered_path = str(td / "tampered_trunc.hcrypt")
        open(tampered_path, "wb").write(raw)

        with pytest.raises((InvalidTag, ValueError)):
            decrypt_file(tampered_path, dec, private_key)

    def test_zero_out_nonce(self, key_pair, tmp):
        """Zeroing the nonce must make decryption produce wrong plaintext or raise."""
        private_key, public_key = key_pair
        enc = self._encrypt_sample(key_pair, tmp)
        mk, td = tmp
        dec = str(td / "tamper_nonce_dec.txt")

        raw = bytearray(open(enc, "rb").read())
        (key_len,) = struct.unpack(_KEY_LEN_FORMAT, raw[:_KEY_LEN_SIZE])
        nonce_start = _KEY_LEN_SIZE + key_len
        raw[nonce_start:nonce_start + NONCE_BYTES] = b"\x00" * NONCE_BYTES
        tampered_path = str(td / "tampered_nonce.hcrypt")
        open(tampered_path, "wb").write(raw)

        with pytest.raises(InvalidTag):
            decrypt_file(tampered_path, dec, private_key)


# ---------------------------------------------------------------------------
# 4. Header / format validation
# ---------------------------------------------------------------------------

class TestHeaderValidation:
    def test_empty_file_raises_value_error(self, key_pair, tmp):
        private_key, _ = key_pair
        mk, td = tmp
        empty = mk("empty.hcrypt", b"")
        dec = str(td / "empty_dec.txt")

        with pytest.raises(ValueError, match="too short"):
            decrypt_file(empty, dec, private_key)

    def test_truncated_key_raises_value_error(self, key_pair, tmp):
        private_key, _ = key_pair
        mk, td = tmp
        # Write a key_len of 512 but provide no actual key bytes
        bad = mk("bad.hcrypt", struct.pack(_KEY_LEN_FORMAT, 512))
        dec = str(td / "bad_dec.txt")

        with pytest.raises(ValueError, match="Truncated encrypted session key"):
            decrypt_file(bad, dec, private_key)
