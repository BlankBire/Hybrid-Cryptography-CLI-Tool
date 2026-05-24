"""Tests for the hybrid cryptography engine.

Test categories:
  1. Round-trip         — encrypt -> decrypt produces original plaintext.
  2. Streaming          — multi-chunk large files decrypt correctly.
  3. Compression        — compress=True/False both work; compressed file is smaller.
  4. Key isolation      — wrong private key cannot decrypt.
  5. Tamper defense     — any modification to the ciphertext raises InvalidTag.
  6. Header/format      — magic bytes, truncated header raise ValueError.
  7. Digital signatures — sign/verify, tampered file, wrong key.
"""

import os
import struct

import pytest
from cryptography.exceptions import InvalidSignature, InvalidTag

from hybrid_crypto.crypto import (
    MAGIC,
    NONCE_BYTES,
    _CHUNK_LEN_SIZE,
    _KEY_LEN_FORMAT,
    _KEY_LEN_SIZE,
    decrypt_file,
    encrypt_file,
)
from hybrid_crypto.keys import generate_rsa_keypair
from hybrid_crypto.signing import sign_file, verify_file


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
    def _make(name: str, content: bytes = b"") -> str:
        path = tmp_path / name
        path.write_bytes(content)
        return str(path)
    return _make, tmp_path


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _cipher_start(raw: bytes) -> int:
    """Return the byte offset where the first chunk's ciphertext begins."""
    flags_offset = len(MAGIC)
    keylen_field_offset = flags_offset + 1
    (key_len,) = struct.unpack(_KEY_LEN_FORMAT, raw[keylen_field_offset: keylen_field_offset + _KEY_LEN_SIZE])
    return keylen_field_offset + _KEY_LEN_SIZE + key_len + NONCE_BYTES + _CHUNK_LEN_SIZE


def _nonce_start(raw: bytes) -> int:
    """Return the byte offset where the base nonce begins."""
    flags_offset = len(MAGIC)
    keylen_field_offset = flags_offset + 1
    (key_len,) = struct.unpack(_KEY_LEN_FORMAT, raw[keylen_field_offset: keylen_field_offset + _KEY_LEN_SIZE])
    return keylen_field_offset + _KEY_LEN_SIZE + key_len


# ---------------------------------------------------------------------------
# 1. Round-trip
# ---------------------------------------------------------------------------

class TestRoundTrip:
    def test_small_plaintext(self, key_pair, tmp):
        mk, td = tmp
        private_key, public_key = key_pair
        src = mk("plain.txt", b"Hello, Hybrid Crypto!")
        enc = str(td / "plain.hcrypt")
        dec = str(td / "plain_dec.txt")

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
        payload = os.urandom(64 * 1024)
        src = mk("random.bin", payload)
        enc = str(td / "random.hcrypt")
        dec = str(td / "random_dec.bin")

        encrypt_file(src, enc, public_key)
        decrypt_file(enc, dec, private_key)

        assert open(dec, "rb").read() == payload

    def test_nondeterministic_ciphertext(self, key_pair, tmp):
        _, public_key = key_pair
        mk, td = tmp
        src = mk("msg.txt", b"Same plaintext")
        enc1 = str(td / "msg1.hcrypt")
        enc2 = str(td / "msg2.hcrypt")

        encrypt_file(src, enc1, public_key)
        encrypt_file(src, enc2, public_key)

        assert open(enc1, "rb").read() != open(enc2, "rb").read()


# ---------------------------------------------------------------------------
# 2. Streaming — large file crosses multiple 64 KB chunks
# ---------------------------------------------------------------------------

class TestStreaming:
    def test_multi_chunk_file(self, key_pair, tmp):
        """1 MB file spans ~16 chunks and must round-trip correctly."""
        private_key, public_key = key_pair
        mk, td = tmp
        payload = os.urandom(1024 * 1024)  # 1 MB
        src = mk("large.bin", payload)
        enc = str(td / "large.hcrypt")
        dec = str(td / "large_dec.bin")

        encrypt_file(src, enc, public_key)
        decrypt_file(enc, dec, private_key)

        assert open(dec, "rb").read() == payload

    def test_exact_chunk_boundary(self, key_pair, tmp):
        """File exactly at CHUNK_SIZE boundary must not produce an empty trailing chunk."""
        from hybrid_crypto.crypto import CHUNK_SIZE

        private_key, public_key = key_pair
        mk, td = tmp
        payload = os.urandom(CHUNK_SIZE)
        src = mk("boundary.bin", payload)
        enc = str(td / "boundary.hcrypt")
        dec = str(td / "boundary_dec.bin")

        encrypt_file(src, enc, public_key)
        decrypt_file(enc, dec, private_key)

        assert open(dec, "rb").read() == payload


# ---------------------------------------------------------------------------
# 3. Compression
# ---------------------------------------------------------------------------

class TestCompression:
    def test_compressed_round_trip(self, key_pair, tmp):
        private_key, public_key = key_pair
        mk, td = tmp
        payload = b"A" * 100_000  # highly compressible
        src = mk("comp.txt", payload)
        enc = str(td / "comp.hcrypt")
        dec = str(td / "comp_dec.txt")

        encrypt_file(src, enc, public_key, compress=True)
        decrypt_file(enc, dec, private_key)

        assert open(dec, "rb").read() == payload

    def test_uncompressed_round_trip(self, key_pair, tmp):
        private_key, public_key = key_pair
        mk, td = tmp
        payload = b"A" * 100_000
        src = mk("nocomp.txt", payload)
        enc = str(td / "nocomp.hcrypt")
        dec = str(td / "nocomp_dec.txt")

        encrypt_file(src, enc, public_key, compress=False)
        decrypt_file(enc, dec, private_key)

        assert open(dec, "rb").read() == payload

    def test_compressed_file_is_smaller(self, key_pair, tmp):
        """Compressible data should produce a smaller .hcrypt than uncompressed."""
        _, public_key = key_pair
        mk, td = tmp
        payload = b"X" * 200_000
        src = mk("big.txt", payload)
        enc_c = str(td / "big_c.hcrypt")
        enc_nc = str(td / "big_nc.hcrypt")

        encrypt_file(src, enc_c, public_key, compress=True)
        encrypt_file(src, enc_nc, public_key, compress=False)

        assert os.path.getsize(enc_c) < os.path.getsize(enc_nc)

    def test_compressed_flag_in_header(self, key_pair, tmp):
        """FLAG_COMPRESSED bit must be set/unset in the flags byte correctly."""
        from hybrid_crypto.crypto import FLAG_COMPRESSED

        _, public_key = key_pair
        mk, td = tmp
        src = mk("flag_test.txt", b"hello")

        enc_c = str(td / "flag_c.hcrypt")
        enc_nc = str(td / "flag_nc.hcrypt")

        encrypt_file(src, enc_c, public_key, compress=True)
        encrypt_file(src, enc_nc, public_key, compress=False)

        flags_offset = len(MAGIC)
        assert open(enc_c, "rb").read()[flags_offset] & FLAG_COMPRESSED
        assert not (open(enc_nc, "rb").read()[flags_offset] & FLAG_COMPRESSED)


# ---------------------------------------------------------------------------
# 4. Key isolation
# ---------------------------------------------------------------------------

class TestKeyIsolation:
    def test_wrong_private_key_fails(self, key_pair, wrong_key_pair, tmp):
        _, public_key = key_pair
        wrong_private_key, _ = wrong_key_pair
        mk, td = tmp
        src = mk("secret.txt", b"Top secret data")
        enc = str(td / "secret.hcrypt")
        dec = str(td / "secret_wrong_dec.txt")

        encrypt_file(src, enc, public_key)

        with pytest.raises(Exception):
            decrypt_file(enc, dec, wrong_private_key)


# ---------------------------------------------------------------------------
# 5. Tamper defense
# ---------------------------------------------------------------------------

class TestTamperDefense:
    def _make_encrypted(self, key_pair, tmp, name="tamper_src.txt"):
        _, public_key = key_pair
        mk, td = tmp
        src = mk(name, b"Sensitive document content that must not be tampered with.")
        enc = str(td / (name + ".hcrypt"))
        encrypt_file(src, enc, public_key)
        return enc

    def test_flip_single_ciphertext_bit(self, key_pair, tmp):
        private_key, _ = key_pair
        enc = self._make_encrypted(key_pair, tmp, "flip_src.txt")
        _, td = tmp
        dec = str(td / "flip_dec.txt")

        raw = bytearray(open(enc, "rb").read())
        raw[_cipher_start(raw)] ^= 0xFF
        tampered = str(td / "flip_tampered.hcrypt")
        open(tampered, "wb").write(raw)

        with pytest.raises(InvalidTag):
            decrypt_file(tampered, dec, private_key)

    def test_inject_garbage_before_eof_sentinel(self, key_pair, tmp):
        """Inserting bytes before the EOF sentinel corrupts the chunk-length field."""
        private_key, _ = key_pair
        enc = self._make_encrypted(key_pair, tmp, "inject_src.txt")
        _, td = tmp
        dec = str(td / "inject_dec.txt")

        # Strip the 4-byte EOF sentinel, inject garbage, re-add the sentinel.
        raw = open(enc, "rb").read()
        raw_without_sentinel = raw[:-4]  # remove b"\x00\x00\x00\x00"
        tampered_data = raw_without_sentinel + b"\xde\xad\xbe\xef" + raw[-4:]
        tampered = str(td / "inject_tampered.hcrypt")
        open(tampered, "wb").write(tampered_data)

        with pytest.raises((InvalidTag, ValueError)):
            decrypt_file(tampered, dec, private_key)

    def test_truncate_auth_tag(self, key_pair, tmp):
        private_key, _ = key_pair
        enc = self._make_encrypted(key_pair, tmp, "trunc_src.txt")
        _, td = tmp
        dec = str(td / "trunc_dec.txt")

        raw = open(enc, "rb").read()[:-16]
        tampered = str(td / "trunc_tampered.hcrypt")
        open(tampered, "wb").write(raw)

        with pytest.raises((InvalidTag, ValueError)):
            decrypt_file(tampered, dec, private_key)

    def test_zero_out_nonce(self, key_pair, tmp):
        private_key, _ = key_pair
        enc = self._make_encrypted(key_pair, tmp, "nonce_src.txt")
        _, td = tmp
        dec = str(td / "nonce_dec.txt")

        raw = bytearray(open(enc, "rb").read())
        ns = _nonce_start(raw)
        raw[ns: ns + NONCE_BYTES] = b"\x00" * NONCE_BYTES
        tampered = str(td / "nonce_tampered.hcrypt")
        open(tampered, "wb").write(raw)

        with pytest.raises(InvalidTag):
            decrypt_file(tampered, dec, private_key)


# ---------------------------------------------------------------------------
# 6. Header / format validation
# ---------------------------------------------------------------------------

class TestHeaderValidation:
    def test_bad_magic_raises_value_error(self, key_pair, tmp):
        private_key, _ = key_pair
        mk, td = tmp
        bad = mk("bad_magic.hcrypt", b"WRONGX" + b"\x00" * 100)
        dec = str(td / "bad_magic_dec.txt")

        with pytest.raises(ValueError, match="bad magic bytes"):
            decrypt_file(bad, dec, private_key)

    def test_empty_file_raises_value_error(self, key_pair, tmp):
        private_key, _ = key_pair
        mk, td = tmp
        empty = mk("empty.hcrypt", b"")
        dec = str(td / "empty_dec.txt")

        with pytest.raises(ValueError, match="bad magic bytes"):
            decrypt_file(empty, dec, private_key)

    def test_truncated_key_raises_value_error(self, key_pair, tmp):
        private_key, _ = key_pair
        mk, td = tmp
        # Proper magic + flags, but key_len=512 with zero actual key bytes
        bad_data = MAGIC + bytes([0x00]) + struct.pack(_KEY_LEN_FORMAT, 512)
        bad = mk("bad_key.hcrypt", bad_data)
        dec = str(td / "bad_key_dec.txt")

        with pytest.raises(ValueError, match="Truncated encrypted session key"):
            decrypt_file(bad, dec, private_key)


# ---------------------------------------------------------------------------
# 7. Digital signatures
# ---------------------------------------------------------------------------

class TestSignatures:
    def test_sign_and_verify(self, key_pair, tmp):
        private_key, public_key = key_pair
        mk, _ = tmp
        src = mk("doc.txt", b"Important document content.")
        sig = sign_file(src, private_key)
        verify_file(src, sig, public_key)  # must not raise

    def test_tampered_file_fails_verification(self, key_pair, tmp):
        private_key, public_key = key_pair
        mk, _ = tmp
        src = mk("doc_t.txt", b"Important document content.")
        sig = sign_file(src, private_key)

        tampered = mk("doc_t_evil.txt", b"Important document TAMPERED.")
        with pytest.raises(InvalidSignature):
            verify_file(tampered, sig, public_key)

    def test_wrong_public_key_fails_verification(self, key_pair, wrong_key_pair, tmp):
        private_key, _ = key_pair
        _, wrong_public_key = wrong_key_pair
        mk, _ = tmp
        src = mk("doc_wk.txt", b"Document for wrong key test.")
        sig = sign_file(src, private_key)

        with pytest.raises(InvalidSignature):
            verify_file(src, sig, wrong_public_key)

    def test_corrupted_signature_fails(self, key_pair, tmp):
        private_key, public_key = key_pair
        mk, _ = tmp
        src = mk("doc_cs.txt", b"Document with corrupted sig.")
        sig = bytearray(sign_file(src, private_key))
        sig[0] ^= 0xFF  # corrupt first byte

        with pytest.raises(InvalidSignature):
            verify_file(src, bytes(sig), public_key)

    def test_large_file_signature(self, key_pair, tmp):
        """Signature must work correctly on a file larger than the internal chunk size."""
        private_key, public_key = key_pair
        mk, _ = tmp
        payload = os.urandom(512 * 1024)  # 512 KB
        src = mk("large_doc.bin", payload)
        sig = sign_file(src, private_key)
        verify_file(src, sig, public_key)  # must not raise
