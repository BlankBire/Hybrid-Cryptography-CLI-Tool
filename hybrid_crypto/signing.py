"""RSA-PSS digital signature — stream-hash then sign/verify."""

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, utils

_CHUNK_SIZE = 64 * 1024


def _sha256_digest(file_path: str) -> bytes:
    """Stream-hash *file_path* with SHA-256, returning the raw digest."""
    hasher = hashes.Hash(hashes.SHA256())
    with open(file_path, "rb") as f:
        while chunk := f.read(_CHUNK_SIZE):
            hasher.update(chunk)
    return hasher.finalize()


def _pss_padding():
    return padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH,
    )


def sign_file(file_path: str, private_key) -> bytes:
    """Return the RSA-PSS signature of *file_path* as raw bytes."""
    return private_key.sign(
        _sha256_digest(file_path),
        _pss_padding(),
        utils.Prehashed(hashes.SHA256()),
    )


def verify_file(file_path: str, signature: bytes, public_key) -> None:
    """Verify *signature* against *file_path*.

    Raises:
        cryptography.exceptions.InvalidSignature — if the file was tampered
            with or the signature was produced by a different private key.
    """
    public_key.verify(
        signature,
        _sha256_digest(file_path),
        _pss_padding(),
        utils.Prehashed(hashes.SHA256()),
    )
