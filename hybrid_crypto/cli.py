"""Command-line interface for the Hybrid Cryptography Tool.

Usage examples:
  python -m hybrid_crypto keygen --out-dir ./keys
  python -m hybrid_crypto encrypt secret.pdf --pub-key ./keys/public.pem --out secret.pdf.hcrypt
  python -m hybrid_crypto decrypt secret.pdf.hcrypt --priv-key ./keys/private.pem --out secret.pdf
"""

import argparse
import getpass
import sys
from pathlib import Path

from .crypto import decrypt_file, encrypt_file
from .keys import (
    generate_rsa_keypair,
    load_private_key,
    load_public_key,
    save_private_key,
    save_public_key,
)


def _cmd_keygen(args: argparse.Namespace) -> None:
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    priv_path = out_dir / "private.pem"
    pub_path = out_dir / "public.pem"

    password: bytes | None = None
    if args.passphrase:
        raw = getpass.getpass("Enter passphrase to protect private key: ")
        confirm = getpass.getpass("Confirm passphrase: ")
        if raw != confirm:
            print("Error: passphrases do not match.", file=sys.stderr)
            sys.exit(1)
        password = raw.encode()

    print("Generating RSA-4096 key pair … (this may take a moment)")
    private_key, public_key = generate_rsa_keypair()

    save_private_key(private_key, priv_path, password)
    save_public_key(public_key, pub_path)

    print(f"Private key saved to: {priv_path}")
    print(f"Public  key saved to: {pub_path}")


def _cmd_encrypt(args: argparse.Namespace) -> None:
    input_path = Path(args.input_file)
    if not input_path.exists():
        print(f"Error: input file not found: {input_path}", file=sys.stderr)
        sys.exit(1)

    output_path = Path(args.out) if args.out else input_path.with_suffix(input_path.suffix + ".hcrypt")

    public_key = load_public_key(args.pub_key)

    print(f"Encrypting {input_path} -> {output_path}")
    encrypt_file(str(input_path), str(output_path), public_key)
    print("Done.")


def _cmd_decrypt(args: argparse.Namespace) -> None:
    input_path = Path(args.input_file)
    if not input_path.exists():
        print(f"Error: input file not found: {input_path}", file=sys.stderr)
        sys.exit(1)

    if args.out:
        output_path = Path(args.out)
    elif input_path.suffix == ".hcrypt":
        output_path = input_path.with_suffix("")
    else:
        output_path = input_path.with_suffix(".decrypted")

    password: bytes | None = None
    if args.passphrase:
        password = getpass.getpass("Enter private key passphrase: ").encode()

    private_key = load_private_key(args.priv_key, password)

    print(f"Decrypting {input_path} -> {output_path}")
    try:
        decrypt_file(str(input_path), str(output_path), private_key)
        print("Done. Integrity check passed.")
    except Exception as exc:  # noqa: BLE001
        print(f"Error: decryption failed — {exc}", file=sys.stderr)
        # Remove partial output to avoid leaving corrupted data on disk
        if output_path.exists():
            output_path.unlink()
        sys.exit(1)


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="hybrid-crypto",
        description="Hybrid RSA-4096-OAEP + AES-GCM-256 file encryption tool.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # --- keygen ---
    p_keygen = subparsers.add_parser("keygen", help="Generate an RSA-4096 key pair.")
    p_keygen.add_argument("--out-dir", default=".", metavar="DIR", help="Directory to write key files (default: current dir).")
    p_keygen.add_argument("--passphrase", action="store_true", help="Encrypt the private key with a passphrase.")
    p_keygen.set_defaults(func=_cmd_keygen)

    # --- encrypt ---
    p_enc = subparsers.add_parser("encrypt", help="Encrypt a file.")
    p_enc.add_argument("input_file", metavar="FILE", help="Path to the file to encrypt.")
    p_enc.add_argument("--pub-key", required=True, metavar="PEM", help="Recipient's public key PEM file.")
    p_enc.add_argument("--out", metavar="OUTPUT", help="Output .hcrypt file path (default: <FILE>.hcrypt).")
    p_enc.set_defaults(func=_cmd_encrypt)

    # --- decrypt ---
    p_dec = subparsers.add_parser("decrypt", help="Decrypt a .hcrypt file.")
    p_dec.add_argument("input_file", metavar="FILE", help="Path to the .hcrypt file.")
    p_dec.add_argument("--priv-key", required=True, metavar="PEM", help="Your private key PEM file.")
    p_dec.add_argument("--out", metavar="OUTPUT", help="Output file path (default: strips .hcrypt extension).")
    p_dec.add_argument("--passphrase", action="store_true", help="Prompt for private key passphrase.")
    p_dec.set_defaults(func=_cmd_decrypt)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
