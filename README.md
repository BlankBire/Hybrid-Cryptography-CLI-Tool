# Hybrid Cryptography CLI Tool

A production-ready command-line tool implementing **PGP-style hybrid encryption**, combining RSA-4096-OAEP (asymmetric key transport) and AES-GCM-256 (authenticated symmetric encryption) to securely encrypt files of arbitrary size.

---

## Table of Contents

- [Why Hybrid Encryption?](#why-hybrid-encryption)
- [How It Works](#how-it-works)
- [Binary File Format (.hcrypt)](#binary-file-format-hcrypt)
- [Installation](#installation)
- [Usage](#usage)
- [Demo: End-to-End Walkthrough](#demo-end-to-end-walkthrough)
- [Security Properties](#security-properties)
- [Test Suite](#test-suite)
- [Project Structure](#project-structure)

---

## Why Hybrid Encryption?

There are two fundamental approaches in cryptography, each with a fatal flaw:

| Approach | Example | Strength | Weakness |
|---|---|---|---|
| **Symmetric** | AES | Blazing fast - encrypts GBs in seconds | How do you securely share the key over the internet? |
| **Asymmetric** | RSA | Public key is safe to share openly | Extremely slow - encrypting a 100 MB file would take minutes |

This tool resolves the dilemma by combining both:

> **Use AES to lock the file** (for speed), then **use RSA to lock the AES key** (for secure key transport).

This is exactly how PGP, TLS, and Signal work under the hood.

---

## How It Works

### Encryption Flow

```
                     os.urandom(32)
                          │
                          ▼
Plaintext ──────► [ AES-GCM-256 ] ──────────────────────► Ciphertext + Auth Tag ──────┐
                          │                                                           │
                    Session Key                                                       │
                          │                                                           ▼
                          └──► [ RSA-4096-OAEP (Public Key) ] ──► Encrypted Key ──► .hcrypt
```

1. Generate a random 256-bit **session key** (lives only for this operation).
2. Encrypt the entire file with **AES-GCM-256** using that session key - fast, regardless of file size.
3. Encrypt the tiny session key with the recipient's **RSA-4096 public key** - safe to transmit.
4. Pack everything into a single **`.hcrypt`** binary file.

### Decryption Flow

```
.hcrypt ──► Encrypted Key ──► [ RSA-4096-OAEP (Private Key) ] ──► Session Key ──┐
                                                                                │
        ──► Ciphertext ─────────────────────────► [ AES-GCM-256 ] ◄─────────────┘
                                                        │
                                                        ▼
                                                   Plaintext ✓
```

An attacker who intercepts the `.hcrypt` file gets nothing, the session key is locked behind the recipient's private key, which never leaves their machine.

---

## Binary File Format (.hcrypt)

The encrypted output uses a custom, deterministic binary layout for cross-platform compatibility:

```
┌─────────────────┬───────────────────────────┬─────────────────┬──────────────────────────────────┐
│  4 bytes        │  512 bytes                │  12 bytes       │  Variable                        │
│  Key Length     │  Encrypted Session Key    │  Nonce (IV)     │  Ciphertext + Auth Tag (16 B)    │
│  (Big-Endian)   │  RSA-4096-OAEP            │  AES-GCM        │  AES-GCM-256 output              │
└─────────────────┴───────────────────────────┴─────────────────┴──────────────────────────────────┘
```

| Field | Size | Description |
|---|---|---|
| Key Length | 4 bytes | Big-endian `uint32` — byte count of the encrypted session key |
| Encrypted Session Key | 512 bytes | 32-byte AES key, RSA-OAEP encrypted with SHA-256 |
| Nonce | 12 bytes | Cryptographically random IV, unique per encryption |
| Ciphertext + Tag | plaintext size + 16 B | AES-GCM output with appended authentication tag |

**Real hex dump** of an 82-byte file encrypted to `.hcrypt`:

```
Offset  Content
------  -------
0x0000  00 00 02 00          ← Key length: 512 bytes (0x200)
0x0004  A5 47 05 57 ...      ← RSA-encrypted session key (512 bytes)
0x0204  F6 B4 2B E4 ...      ← AES-GCM nonce (12 bytes)
0x0210  14 F6 23 0A ...      ← Ciphertext + 16-byte auth tag
```

Total overhead per file: **528 bytes** (4 + 512 + 12).

---

## Installation

**Requirements:** Python 3.10+

```bash
git clone https://github.com/BlankBire/Hybrid-Cryptography-CLI-Tool.git
cd Hybrid-Cryptography-CLI-Tool

pip install -r requirements.txt
```

Or install as a CLI command globally:

```bash
pip install -e .
```

After installing with `-e`, the `hybrid-crypto` command becomes available system-wide.

---

## Usage

### 1. Generate a Key Pair

```bash
python -m hybrid_crypto keygen --out-dir ./keys
```

```
Generating RSA-4096 key pair ... (this may take a moment)
Private key saved to: keys\private.pem
Public  key saved to: keys\public.pem
```

Optional: protect the private key with a passphrase:

```bash
python -m hybrid_crypto keygen --out-dir ./keys --passphrase
```

---

### 2. Encrypt a File

```bash
python -m hybrid_crypto encrypt secret.txt --pub-key ./keys/public.pem
```

```
Encrypting secret.txt -> secret.txt.hcrypt
Done.
```

Custom output path:

```bash
python -m hybrid_crypto encrypt report.pdf --pub-key ./keys/public.pem --out report_encrypted.hcrypt
```

---

### 3. Decrypt a File

```bash
python -m hybrid_crypto decrypt secret.txt.hcrypt --priv-key ./keys/private.pem
```

```
Decrypting secret.txt.hcrypt -> secret.txt
Done. Integrity check passed.
```

If the private key is passphrase-protected:

```bash
python -m hybrid_crypto decrypt secret.txt.hcrypt --priv-key ./keys/private.pem --passphrase
```

---

### Full Options Reference

```
usage: hybrid-crypto [-h] {keygen,encrypt,decrypt} ...

Commands:
  keygen    Generate an RSA-4096 key pair.
  encrypt   Encrypt a file.
  decrypt   Decrypt a .hcrypt file.

keygen:
  --out-dir DIR    Directory to write key files (default: current dir)
  --passphrase     Encrypt the private key with a passphrase

encrypt:
  FILE             Path to the file to encrypt
  --pub-key PEM    Recipient's public key PEM file  [required]
  --out OUTPUT     Output .hcrypt file path (default: <FILE>.hcrypt)

decrypt:
  FILE             Path to the .hcrypt file
  --priv-key PEM   Your private key PEM file  [required]
  --out OUTPUT     Output file path (default: strips .hcrypt extension)
  --passphrase     Prompt for private key passphrase
```

---

## Demo: End-to-End Walkthrough

### Setup

```bash
python -m hybrid_crypto keygen --out-dir ./demo_keys
```

```
Generating RSA-4096 key pair ... (this may take a moment)
Private key saved to: demo_keys\private.pem
Public  key saved to: demo_keys\public.pem
```

---

### Encrypt a Secret File

```
$ cat demo_secret.txt
Day la tai lieu mat.
Chia khoa ngan hang: 123456
Mat khau server: SuperSecret@2026

$ python -m hybrid_crypto encrypt demo_secret.txt --pub-key ./demo_keys/public.pem --out demo_secret.hcrypt
Encrypting demo_secret.txt -> demo_secret.hcrypt
Done.
```

**Size comparison:**

```
demo_secret.txt    :  82 bytes  ← plaintext
demo_secret.hcrypt : 626 bytes  ← 4 header + 512 RSA key + 12 nonce + 82 data + 16 auth tag
```

---

### Decrypt and Verify

```
$ python -m hybrid_crypto decrypt demo_secret.hcrypt --priv-key ./demo_keys/private.pem --out demo_secret_recovered.txt
Decrypting demo_secret.hcrypt -> demo_secret_recovered.txt
Done. Integrity check passed.

$ cat demo_secret_recovered.txt
Day la tai lieu mat.
Chia khoa ngan hang: 123456
Mat khau server: SuperSecret@2026

Byte-for-byte match: True
```

---

### Tamper Attack Simulation

An attacker intercepts the file and flips a single bit in the ciphertext:

```python
# Attacker flips byte at offset 528: 0x14 -> 0xEB
data[cipher_start] ^= 0xFF
```

Result when the recipient tries to decrypt:

```
$ python -m hybrid_crypto decrypt demo_tampered.hcrypt --priv-key ./demo_keys/private.pem --out out.txt
Decrypting demo_tampered.hcrypt -> out.txt
Error: decryption failed — [InvalidTag]

Exit code: 1
```

**AES-GCM detects the tampering immediately and refuses to produce any output.** Not a single byte of corrupted plaintext is written to disk. This is the authentication guarantee of GCM mode - modifying even one bit of the ciphertext invalidates the 16-byte authentication tag.

---

## Security Properties

| Property | Implementation | Guarantee |
|---|---|---|
| **Confidentiality** | AES-256-GCM | Computationally infeasible to decrypt without the private key |
| **Integrity** | GCM authentication tag (16 bytes) | Any modification to the ciphertext is detected on decryption |
| **Authenticity** | RSA-4096-OAEP with SHA-256 | Session key can only be decrypted by the holder of the private key |
| **Semantic security** | Random session key + random nonce per encryption | Encrypting the same file twice produces completely different ciphertext |
| **Forward secrecy (per-file)** | Ephemeral session key discarded after use | Compromising one session key does not affect other files |

### Why AES-GCM over AES-CBC?

CBC (Cipher Block Chaining) is an older mode that provides **confidentiality only** - an attacker can silently flip bits in the ciphertext and alter the decrypted plaintext without detection (bit-flipping attack). GCM (Galois/Counter Mode) is an **Authenticated Encryption with Associated Data (AEAD)** mode: it simultaneously encrypts and computes a cryptographic MAC over the data. Tampering is impossible without detection.

### Why RSA-OAEP over RSA-PKCS1v1.5?

PKCS#1 v1.5 padding is vulnerable to Bleichenbacher's 1998 padding oracle attack. OAEP (Optimal Asymmetric Encryption Padding) with SHA-256 is the modern, provably secure alternative and is required by NIST SP 800-131A.

---

## Test Suite

```
$ python -m pytest tests/ -v

============================= test session starts =============================
platform win32 -- Python 3.12.0, pytest-9.0.3
collected 11 items

tests/test_crypto.py::TestRoundTrip::test_small_plaintext                        PASSED
tests/test_crypto.py::TestRoundTrip::test_empty_file                             PASSED
tests/test_crypto.py::TestRoundTrip::test_binary_content                         PASSED
tests/test_crypto.py::TestRoundTrip::test_each_encryption_produces_different_ciphertext  PASSED
tests/test_crypto.py::TestKeyIsolation::test_wrong_private_key_fails             PASSED
tests/test_crypto.py::TestTamperDefense::test_flip_single_ciphertext_bit         PASSED
tests/test_crypto.py::TestTamperDefense::test_append_garbage_bytes               PASSED
tests/test_crypto.py::TestTamperDefense::test_truncate_auth_tag                  PASSED
tests/test_crypto.py::TestTamperDefense::test_zero_out_nonce                     PASSED
tests/test_crypto.py::TestHeaderValidation::test_empty_file_raises_value_error   PASSED
tests/test_crypto.py::TestHeaderValidation::test_truncated_key_raises_value_error PASSED

============================= 11 passed in 0.29s ==============================
```

| Category | Tests | What is verified |
|---|---|---|
| **Round-trip** | 4 | Encrypt → decrypt produces identical bytes; ciphertext is non-deterministic |
| **Key isolation** | 1 | Wrong private key cannot decrypt |
| **Tamper defense** | 4 | Bit flip, appended bytes, truncated tag, zeroed nonce - all raise `InvalidTag` |
| **Header validation** | 2 | Empty file and truncated header raise `ValueError` before any crypto |

---

## Project Structure

```
Hybrid-Cryptography-CLI-Tool/
├── hybrid_crypto/
│   ├── __init__.py      # Package metadata
│   ├── __main__.py      # Enables: python -m hybrid_crypto
│   ├── keys.py          # RSA-4096 key generation and PEM serialization
│   ├── crypto.py        # Core encrypt/decrypt engine + .hcrypt binary format
│   └── cli.py           # argparse CLI: keygen / encrypt / decrypt
├── tests/
│   └── test_crypto.py   # 11 tests across 4 categories
├── .gitignore
├── requirements.txt
├── setup.py
└── README.md
```

---

## Dependencies

| Package | Version | Purpose |
|---|---|---|
| `cryptography` | ≥ 42.0.0 | RSA-OAEP, AES-GCM, PEM serialization (PyCA - industry standard) |
| `pytest` | ≥ 8.0.0 | Test runner |

---

## License

MIT
