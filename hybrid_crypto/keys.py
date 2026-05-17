"""RSA-4096 key generation and PEM serialization utilities."""

from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def generate_rsa_keypair(key_size: int = 4096) -> tuple:
    """Generate an RSA key pair and return (private_key, public_key)."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )
    return private_key, private_key.public_key()


def save_private_key(private_key, path: Path, password: bytes | None = None) -> None:
    """Serialize and write a private key to a PEM file.

    If password is provided the key is encrypted with AES-256-CBC (PKCS8).
    """
    if password:
        encryption = serialization.BestAvailableEncryption(password)
    else:
        encryption = serialization.NoEncryption()

    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption,
    )
    Path(path).write_bytes(pem)


def save_public_key(public_key, path: Path) -> None:
    """Serialize and write a public key to a PEM file."""
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    Path(path).write_bytes(pem)


def load_private_key(path: Path, password: bytes | None = None):
    """Load and return an RSA private key from a PEM file."""
    return serialization.load_pem_private_key(
        Path(path).read_bytes(),
        password=password,
    )


def load_public_key(path: Path):
    """Load and return an RSA public key from a PEM file."""
    return serialization.load_pem_public_key(Path(path).read_bytes())
