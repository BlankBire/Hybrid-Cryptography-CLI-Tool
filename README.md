# Hybrid Cryptography CLI Tool

A production-ready command-line tool implementing **PGP-style hybrid encryption**, combining RSA-4096-OAEP (asymmetric key transport) and AES-GCM-256 (authenticated symmetric encryption) to securely encrypt files of arbitrary size, with streaming I/O, built-in compression, digital signatures, and a versioned binary format.

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
Plaintext ──► [zlib compress] ──► [ AES-GCM-256 ] ──► Ciphertext + Auth Tag ──┐
  (chunk         (per chunk)             │                   (per chunk)       │
  64 KB each)                      Session Key                                 │
                                         │                                     ▼
                                         └──► [ RSA-4096-OAEP ] ──► Encrypted Key ──► .hcrypt
                                               (Public Key)
```

1. Generate a random 256-bit **session key** (ephemeral - lives only for this operation).
2. Read the input file in **64 KB chunks** - memory usage stays constant regardless of file size.
3. Each chunk is **zlib-compressed** then **AES-GCM-256 encrypted** with a unique per-chunk nonce.
4. The tiny session key is wrapped with the recipient's **RSA-4096 public key** (safe to transmit).
5. Everything is packed into a single **`.hcrypt`** binary file with a versioned header.

### Decryption Flow

```
.hcrypt ──► Encrypted Key ──► [ RSA-4096-OAEP (Private Key) ] ──► Session Key ──┐
                                                                                 │
        ──► Chunk 0 ─────────────────► [ AES-GCM-256 ] ──► decompress ──► plain │
        ──► Chunk 1 ─────────────────► [ AES-GCM-256 ] ──► decompress ──► plain │◄─┘
        ──► ...                                                                  │
        ──► Sentinel (0x00000000) ──► stop                                      ▼
                                                               Original File ✓
```

An attacker who intercepts the `.hcrypt` file gets nothing, the session key is locked behind the recipient's private key, which never leaves their machine. Each chunk has an independent authentication tag, so tampering with any byte triggers an `InvalidTag` error before any plaintext is written to disk.

### Digital Signature Flow

```
File ──► [SHA-256 stream hash] ──► digest ──► [RSA-PSS (Private Key)] ──► .sig

File + .sig + Public Key ──► [RSA-PSS verify] ──► VALID / INVALID
```

The sender signs the file with their **RSA private key**. Anyone with the sender's **public key** can verify that the file is authentic and untampered, without needing any shared secret.

---

## Binary File Format (.hcrypt)

The encrypted output uses a custom, deterministic binary layout for cross-platform compatibility:

```
┌──────────┬──────────┬───────────┬──────────────────────┬──────────┬──────────────────────────────────┐
│ 6 bytes  │ 1 byte   │ 4 bytes   │ 512 bytes            │ 12 bytes │ Repeated chunks until sentinel   │
│ Magic +  │ Flags    │ Key       │ Encrypted            │ Base     ├────────────┬─────────────────────┤
│ Version  │ bit0=zip │ Length    │ Session Key          │ Nonce    │ 4B ChunkLen│ Ciphertext + Tag    │
│ HCRYv1.0 │          │ (BE uint) │ RSA-4096-OAEP        │ AES-GCM  │ 0=sentinel │ (ChunkLen bytes)    │
└──────────┴──────────┴───────────┴──────────────────────┴──────────┴────────────┴─────────────────────┘
```

| Field | Size | Description |
|---|---|---|
| Magic + Version | 6 bytes | `HCRY\x01\x00` - file identifier + major.minor version for forward compatibility |
| Flags | 1 byte | Bitmask: `bit 0` = zlib-compressed chunks |
| Key Length | 4 bytes | Big-endian `uint32` - byte count of the encrypted session key |
| Encrypted Session Key | 512 bytes | 32-byte AES key wrapped with RSA-OAEP (SHA-256) |
| Base Nonce | 12 bytes | Cryptographically random 96-bit IV |
| Chunk Length | 4 bytes | Ciphertext size for this chunk (value `0` = end-of-stream sentinel) |
| Ciphertext + Tag | ChunkLen bytes | AES-GCM output including 16-byte authentication tag |

**Per-chunk nonce derivation:** `nonce_i = base_nonce XOR (i as big-endian uint32 in last 4 bytes)`, guarantees every chunk uses a unique nonce with no extra storage overhead.

Real hex dump of an 82-byte file encrypted to `.hcrypt`:

```
Offset  Content
------  -------
0x0000  48 43 52 59 01 00       ← Magic: "HCRY" + version 1.0
0x0006  01                      ← Flags: 0x01 = compressed
0x0007  00 00 02 00             ← Key length: 512 bytes (0x200)
0x000B  47 54 42 5C ...         ← RSA-encrypted session key (512 bytes)
0x020B  41 DC 21 3C ...         ← Base nonce (12 bytes)
0x0217  00 00 00 68             ← Chunk 0 length: 104 bytes (compressed + 16B tag)
0x021B  29 86 63 AB ...         ← Chunk 0 ciphertext
0x0283  00 00 00 00             ← EOF sentinel
```

Fixed overhead per file: **535 bytes** (6 + 1 + 4 + 512 + 12) + 4 bytes per chunk header + 4 bytes sentinel.

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
  Compression: enabled (zlib)
Done.
```

Disable compression (for already-compressed formats like `.zip`, `.mp4`):

```bash
python -m hybrid_crypto encrypt video.mp4 --pub-key ./keys/public.pem --no-compress
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

---

### 4. Sign a File

```bash
python -m hybrid_crypto sign secret.txt --priv-key ./keys/private.pem
```

```
Signing secret.txt -> secret.txt.sig
Done. Signature size: 512 bytes.
```

---

### 5. Verify a Signature

```bash
python -m hybrid_crypto verify secret.txt --sig secret.txt.sig --pub-key ./keys/public.pem
```

```
Verifying secret.txt against secret.txt.sig ...
Signature is VALID. File is authentic and untampered.
```

---

### Full Options Reference

```
usage: hybrid-crypto [-h] {keygen,encrypt,decrypt,sign,verify} ...

Commands:
  keygen    Generate an RSA-4096 key pair.
  encrypt   Encrypt a file.
  decrypt   Decrypt a .hcrypt file.
  sign      Sign a file with your private key (RSA-PSS).
  verify    Verify a file signature.

keygen:
  --out-dir DIR    Directory to write key files (default: current dir)
  --passphrase     Encrypt the private key with a passphrase

encrypt:
  FILE             Path to the file to encrypt
  --pub-key PEM    Recipient's public key PEM file  [required]
  --out OUTPUT     Output .hcrypt file path (default: <FILE>.hcrypt)
  --no-compress    Disable zlib compression before encryption

decrypt:
  FILE             Path to the .hcrypt file
  --priv-key PEM   Your private key PEM file  [required]
  --out OUTPUT     Output file path (default: strips .hcrypt extension)
  --passphrase     Prompt for private key passphrase

sign:
  FILE             Path to the file to sign
  --priv-key PEM   Your private key PEM file  [required]
  --out OUTPUT     Output .sig file path (default: <FILE>.sig)
  --passphrase     Prompt for private key passphrase

verify:
  FILE             Path to the file to verify
  --sig SIG        The .sig file  [required]
  --pub-key PEM    Signer's public key PEM file  [required]
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

### Encrypt and Decrypt

```
$ cat demo_secret.txt
Day la tai lieu mat.
Chia khoa ngan hang: 123456
Mat khau server: SuperSecret@2026

$ python -m hybrid_crypto encrypt demo_secret.txt --pub-key ./demo_keys/public.pem --out demo_secret.hcrypt
Encrypting demo_secret.txt -> demo_secret.hcrypt
  Compression: enabled (zlib)
Done.
```

**Size breakdown:**

```
demo_secret.txt   :  82 bytes   (plaintext)
demo_secret.hcrypt: 647 bytes
  = 6 magic + 1 flags + 4 key_len + 512 RSA key + 12 nonce
  + 4 chunk_len + 82 data + 16 auth tag + 4 sentinel
```

```
$ python -m hybrid_crypto decrypt demo_secret.hcrypt --priv-key ./demo_keys/private.pem --out demo_secret_recovered.txt
Decrypting demo_secret.hcrypt -> demo_secret_recovered.txt
Done. Integrity check passed.

Byte-for-byte match: True
```

---

### Sign and Verify

```
$ python -m hybrid_crypto sign demo_secret.txt --priv-key ./demo_keys/private.pem --out demo_secret.sig
Signing demo_secret.txt -> demo_secret.sig
Done. Signature size: 512 bytes.

$ python -m hybrid_crypto verify demo_secret.txt --sig demo_secret.sig --pub-key ./demo_keys/public.pem
Verifying demo_secret.txt against demo_secret.sig ...
Signature is VALID. File is authentic and untampered.
```

If the file is tampered with:

```
$ python -m hybrid_crypto verify demo_secret_tampered.txt --sig demo_secret.sig --pub-key ./demo_keys/public.pem
Verifying demo_secret_tampered.txt against demo_secret.sig ...
Signature is INVALID. File may have been tampered with.

Exit code: 1
```

---

### Tamper Attack Simulation

An attacker intercepts the `.hcrypt` file and flips a single bit in the ciphertext:

```python
# Attacker flips byte at offset 539: 0x29 -> 0xD6
data[cipher_start] ^= 0xFF
```

Result when the recipient tries to decrypt:

```
$ python -m hybrid_crypto decrypt demo_tampered.hcrypt --priv-key ./demo_keys/private.pem --out out.txt
Decrypting demo_tampered.hcrypt -> out.txt
Error: decryption failed -- [InvalidTag]

Exit code: 1
```

AES-GCM detects the tampering immediately and refuses to produce any output. Not a single byte of corrupted plaintext is written to disk. This is the authentication guarantee of GCM mode - modifying even one bit of any chunk invalidates that chunk's 16-byte authentication tag.

---

## Security Properties

| Property | Implementation | Guarantee |
|---|---|---|
| **Confidentiality** | AES-256-GCM | Computationally infeasible to decrypt without the private key |
| **Integrity** | GCM authentication tag (16 bytes per chunk) | Any modification to any chunk is detected on decryption |
| **Key transport** | RSA-4096-OAEP with SHA-256 | Session key can only be decrypted by the holder of the private key |
| **Sender authentication** | RSA-PSS with SHA-256 | Signature proves the file was signed by the holder of the private key |
| **Semantic security** | Random session key + random nonce per encryption | Encrypting the same file twice produces completely different ciphertext |
| **Forward secrecy (per-file)** | Ephemeral session key discarded after use | Compromising one file's session key reveals nothing about other files |
| **Format integrity** | Magic bytes `HCRY\x01\x00` | Non-.hcrypt files are rejected before any cryptographic operation |

### Why AES-GCM over AES-CBC?

CBC (Cipher Block Chaining) provides confidentiality only. An attacker can silently flip bits in the ciphertext and alter the decrypted plaintext without detection (bit-flipping attack). GCM (Galois/Counter Mode) is an **AEAD** (Authenticated Encryption with Associated Data) mode: it simultaneously encrypts and computes a cryptographic MAC. Tampering is impossible without detection.

### Why RSA-OAEP over RSA-PKCS1v1.5?

PKCS#1 v1.5 padding is vulnerable to Bleichenbacher's 1998 padding oracle attack. OAEP (Optimal Asymmetric Encryption Padding) with SHA-256 is the modern, provably secure alternative and is required by NIST SP 800-131A.

### Why RSA-PSS for signatures?

RSA-PSS (Probabilistic Signature Scheme) uses a random salt, making two signatures of the same file different, preventing certain existential forgery attacks possible against deterministic signature schemes. PSS is the PKCS#1 v2.1 recommendation for new systems.

---

## Test Suite

```
$ python -m pytest tests/ -v

============================= test session starts =============================
platform win32 -- Python 3.12.0, pytest-9.0.3
collected 23 items

tests/test_crypto.py::TestRoundTrip::test_small_plaintext                               PASSED
tests/test_crypto.py::TestRoundTrip::test_empty_file                                    PASSED
tests/test_crypto.py::TestRoundTrip::test_binary_content                                PASSED
tests/test_crypto.py::TestRoundTrip::test_nondeterministic_ciphertext                   PASSED
tests/test_crypto.py::TestStreaming::test_multi_chunk_file                              PASSED
tests/test_crypto.py::TestStreaming::test_exact_chunk_boundary                          PASSED
tests/test_crypto.py::TestCompression::test_compressed_round_trip                       PASSED
tests/test_crypto.py::TestCompression::test_uncompressed_round_trip                     PASSED
tests/test_crypto.py::TestCompression::test_compressed_file_is_smaller                  PASSED
tests/test_crypto.py::TestCompression::test_compressed_flag_in_header                   PASSED
tests/test_crypto.py::TestKeyIsolation::test_wrong_private_key_fails                    PASSED
tests/test_crypto.py::TestTamperDefense::test_flip_single_ciphertext_bit                PASSED
tests/test_crypto.py::TestTamperDefense::test_inject_garbage_before_eof_sentinel        PASSED
tests/test_crypto.py::TestTamperDefense::test_truncate_auth_tag                         PASSED
tests/test_crypto.py::TestTamperDefense::test_zero_out_nonce                            PASSED
tests/test_crypto.py::TestHeaderValidation::test_bad_magic_raises_value_error           PASSED
tests/test_crypto.py::TestHeaderValidation::test_empty_file_raises_value_error          PASSED
tests/test_crypto.py::TestHeaderValidation::test_truncated_key_raises_value_error       PASSED
tests/test_crypto.py::TestSignatures::test_sign_and_verify                              PASSED
tests/test_crypto.py::TestSignatures::test_tampered_file_fails_verification             PASSED
tests/test_crypto.py::TestSignatures::test_wrong_public_key_fails_verification          PASSED
tests/test_crypto.py::TestSignatures::test_corrupted_signature_fails                    PASSED
tests/test_crypto.py::TestSignatures::test_large_file_signature                         PASSED

============================= 23 passed in 0.83s ==============================
```

| Category | Tests | What is verified |
|---|---|---|
| **Round-trip** | 4 | Encrypt -> decrypt produces identical bytes; ciphertext is non-deterministic |
| **Streaming** | 2 | 1 MB multi-chunk file and exact chunk-boundary file both round-trip correctly |
| **Compression** | 4 | compress=True/False both work; flag is correctly set in header; compressed is smaller |
| **Key isolation** | 1 | Wrong private key cannot decrypt |
| **Tamper defense** | 4 | Bit flip, injected bytes, truncated tag, zeroed nonce - all raise `InvalidTag` |
| **Header validation** | 3 | Bad magic, empty file, truncated key - all raise `ValueError` before any crypto |
| **Digital signatures** | 5 | Sign+verify, tampered file, wrong key, corrupted signature, large file |

---

## Project Structure

```
Hybrid-Cryptography-CLI-Tool/
├── hybrid_crypto/
│   ├── __init__.py      # Package metadata
│   ├── __main__.py      # Enables: python -m hybrid_crypto
│   ├── keys.py          # RSA-4096 key generation and PEM serialization
│   ├── crypto.py        # Streaming encrypt/decrypt + .hcrypt binary format
│   ├── signing.py       # RSA-PSS sign/verify with streaming SHA-256
│   └── cli.py           # argparse CLI: keygen / encrypt / decrypt / sign / verify
├── tests/
│   └── test_crypto.py   # 23 tests across 7 categories
├── .gitignore
├── requirements.txt
├── setup.py
└── README.md
```

---

## Dependencies

| Package | Version | Purpose |
|---|---|---|
| `cryptography` | >= 42.0.0 | RSA-OAEP, AES-GCM, RSA-PSS, PEM serialization (PyCA - industry standard) |
| `pytest` | >= 8.0.0 | Test runner |

---

## License

This project is licensed under the [MIT License](LICENSE).
