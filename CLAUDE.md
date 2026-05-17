# CLAUDE.md - Integrated Project Guide, Codebase & Context

## 1. Project Overview
A production-ready, lightweight Hybrid Cryptography CLI Tool written in Python. It implements a secure PGP-like encryption mechanism combining asymmetric key transport (RSA-4096-OAEP) and symmetric authenticated encryption (AES-GCM-256) to safely process files of arbitrary sizes without memory exhaustion or security degradation.

---

## 2. Cryptographic Architecture & File Format

### Binary Layout Specification (`.hcrypt`)
To ensure cross-platform compatibility and deterministic parsing, the encrypted output file utilizes a custom binary packing layout:

+-------------------+---------------------------+-----------------+-------------------------------+
| Length (4 bytes)  | Encrypted Key (512 bytes) | Nonce (12 bytes)| Ciphertext + Tag (Variable)   |
+-------------------+---------------------------+-----------------+-------------------------------+


*   **Encrypted Key Length:** 4 bytes, Big-Endian integer (`>I`), defining the exact size of the RSA-encrypted session key.
*   **Encrypted Session Key:** Variable size (exactly 512 bytes for RSA-4096), holding the AES-GCM session key encrypted via RSA-OAEP.
*   **Nonce (IV):** 12 bytes of cryptographically secure random data, unique per encryption operation.
*   **Ciphertext + Auth Tag:** The remaining bytes containing the encrypted file data appended with the 16-byte GCM authentication tag.

### Data Flow Diagram
[Encryption Flow]
File Data ----------> [ AES-GCM-256 ] -------------------------> Ciphertext + Tag

^                                                          |---> Output (.hcrypt)
Random Session Key ------+----> [ RSA-4096-OAEP (Public Key) ] -> Encrypted Key     /

[Decryption Flow]
Input (.hcrypt) ----> Encrypted Key -> [ RSA-4096-OAEP (Private Key) ] -> Session Key

----> Ciphertext ----> [ AES-GCM-256 (Session Key) ]  -> Original File /


---