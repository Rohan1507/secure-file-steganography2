# PROJECT REPORT
## Secure File Sharing with Steganography

---

## 1. Abstract

This project implements a web-based secure file-sharing system that combines
authenticated encryption with image steganography. A sender's secret file is
first encrypted using AES-256-GCM, then the resulting ciphertext — along
with the metadata needed to reconstruct it — is embedded into a cover image
using Least Significant Bit (LSB) substitution. The result is a "stego
image" that is visually indistinguishable from the original at normal
viewing conditions but carries the hidden, encrypted file inside it. A
receiver with the correct password can extract the payload, decrypt it, and
verify its integrity via SHA-256 hashing before recovering the original
file byte-for-byte. The system is built with Flask, SQLAlchemy, Pillow, and
the Python `cryptography` library, and includes a full authentication
system, a live capacity calculator, a security/quality analysis dashboard
(MSE, PSNR, SSIM, chi-square steganalysis), and an automated test suite
covering the full encrypt→embed→extract→decrypt→verify pipeline.

## 2. Introduction

Digital communication increasingly requires not just confidentiality but
also discretion — hiding the fact that a secret is being transmitted at
all. Two complementary techniques address this: cryptography, which makes a
message unreadable without a key, and steganography, which hides the
message's existence altogether. Used together, they provide layered
protection: an observer must first detect that a communication channel is
carrying hidden data, and even then must break strong encryption to read
it. This project demonstrates that combination as a working, end-to-end
system suitable for academic evaluation.

## 3. Problem Statement

Sending sensitive files over ordinary channels (email attachments, chat
apps, cloud links) has two weaknesses: (a) if the channel is monitored, an
encrypted attachment is itself a signal that something confidential is
being sent, inviting scrutiny; and (b) many casual file-sharing methods do
not guarantee content integrity or authenticity on arrival. This project
addresses both: the secret is hidden inside an innocuous-looking image
(addressing detectability) and protected with authenticated encryption that
verifies both confidentiality and integrity (addressing tampering).

## 4. Objectives

1. Encrypt a secret file with a modern authenticated cipher before hiding it.
2. Embed the encrypted payload into a cover image using LSB steganography
   without visibly altering the image.
3. Reliably extract, decrypt, and verify the file on the receiving end.
4. Provide accurate capacity calculation so large files are rejected
   clearly, never silently truncated.
5. Offer measurable quality/security metrics (MSE, PSNR, SSIM, chi-square)
   so the concealment quality can be evaluated, not just assumed.
6. Implement complete, working user authentication and per-user history —
   not a mockup.

## 5. Existing System

Conventional secure file-sharing relies purely on encryption (e.g., sending
a password-protected ZIP or PGP-encrypted file). This protects content but
does nothing to hide that a secret exchange is occurring — the encrypted
blob is visibly "not a normal file," which can itself draw attention in
monitored or adversarial environments. Pure steganography tools, on the
other hand, often hide raw plaintext data with no encryption layer, so if
the hidden channel is ever discovered, the content is immediately readable.

## 6. Proposed System

This project layers both techniques:

```
Secret File → AES-256-GCM Encryption → Structured Payload → LSB Embedding
→ Stego Image → Transfer → LSB Extraction → Payload Parsing
→ AES-256-GCM Decryption → SHA-256 Integrity Check → Original File
```

The cover image never contains plaintext. Encryption happens first, so even
a successful extraction yields only ciphertext without the password. The
payload also carries a SHA-256 hash of the *original* plaintext, allowing
the receiver to cryptographically confirm the recovered file is unmodified.

## 7. System Requirements

### 7.1 Hardware Requirements
- Any modern PC/laptop capable of running Python 3.10+
- Minimum 4 GB RAM (image array operations use NumPy in memory)
- ~200 MB free disk space for dependencies and generated files

### 7.2 Software Requirements
- Python 3.10 or later
- pip (Python package manager)
- A modern web browser (Chrome, Firefox, Edge)
- Operating System: Windows, Linux, or macOS

## 8. System Architecture

The application follows a layered MVC-style Flask architecture:

```
┌─────────────────────────────────────────────────┐
│                  Templates (Jinja2)               │
│   index / register / login / dashboard / embed /  │
│   extract / analysis / history / help              │
└───────────────────────┬───────────────────────────┘
                         │
┌───────────────────────▼───────────────────────────┐
│                 Routes (Blueprints)                │
│  auth.py  dashboard.py  steganography.py  analysis.py │
└───────────────────────┬───────────────────────────┘
                         │
┌───────────────────────▼───────────────────────────┐
│                    Services Layer                  │
│ crypto_service │ stego_service │ analysis_service   │
│ file_service   │ audio_stego (optional)             │
└───────────────────────┬───────────────────────────┘
                         │
┌───────────────────────▼───────────────────────────┐
│         SQLAlchemy Models / SQLite Database         │
│   User │ FileOperation │ StegoFile │ SecurityAnalysis│
└─────────────────────────────────────────────────────┘
```

Each layer has a single responsibility: routes handle HTTP concerns and
validation, services implement the actual cryptography/steganography/
analysis logic (independently testable), and models define persistence.

## 9. Data Flow

**Embed flow:**
`User uploads cover image + secret file + password` → `file_service`
validates and safely stores the cover → `stego_service.calculate_capacity`
checks the image can hold the payload → `crypto_service.encrypt_data`
performs AES-256-GCM encryption → `stego_service.build_payload` packs
metadata + ciphertext → `stego_service.embed_payload_into_image` writes
LSBs → stego PNG saved to `generated/` → `StegoFile` and `FileOperation`
records created in the database → download link returned to the user.

**Extract flow:**
`User uploads stego image + password` → `stego_service.extract_payload_from_image`
reads LSBs → `stego_service.parse_payload` reconstructs the structure →
`crypto_service.decrypt_data` performs AES-256-GCM decryption (fails loudly
and safely on wrong password/corruption) → SHA-256 of decrypted bytes is
compared against the hash stored in the payload → recovered file saved and
offered for download → `FileOperation` record created with PASS/FAIL
verification status.

## 10. Methodology

The project was implemented incrementally: cryptography primitives were
built and unit-tested first (in isolation from Flask), then the LSB
steganography engine (with its own bit-manipulation tests), then the two
were combined into the full pipeline and validated with a parametrized
end-to-end test asserting byte-for-byte and hash-for-hash equality between
original and recovered files across multiple content types (text, binary,
PDF-like). Only after the core pipeline was proven correct was the Flask
web layer (auth, routes, templates) built around it, followed by the
security-analysis module and finally a live HTTP-level smoke test that
exercises the actual running server exactly as a browser would.

## 11. LSB Algorithm

**Concept.** Every color channel byte (Red, Green, Blue) of a pixel ranges
from 0–255. The least significant bit is the smallest binary digit of that
byte. Overwriting it changes the channel value by at most ±1 — a shift far
below the threshold of human color perception, but reliably reversible.

**Embedding algorithm:**
```
INPUT: cover image C, payload bytes P
STEP 1: Convert C to an RGB pixel array; flatten to a 1-D byte stream
        of R, G, B, R, G, B, ... values.
STEP 2: Compute a 32-bit big-endian length prefix L = len(P).
STEP 3: Concatenate L's bits with P's bits → full_bits.
STEP 4: If len(full_bits) > available capacity (image_pixels × 3),
        raise InsufficientCapacityError. Never truncate silently.
STEP 5: For each of the first len(full_bits) bytes in the flattened
        array: clear its LSB (AND with 0xFE), then OR in the
        corresponding payload bit.
STEP 6: Reshape the modified array back into image dimensions and
        save as PNG (lossless — required so LSBs survive unchanged).
OUTPUT: stego image
```

**Extraction algorithm:**
```
INPUT: stego image S
STEP 1: Convert S to an RGB pixel array; flatten as in embedding.
STEP 2: Read the first 32 bits (LSB of the first 32 channel bytes)
        to recover the payload length L.
STEP 3: Sanity-check L against the image's actual capacity; if
        implausible, raise NoPayloadFoundError.
STEP 4: Read the next L × 8 bits and pack them back into bytes → payload.
STEP 5: Verify the payload starts with the 4-byte magic identifier
        "STG1"; if not, raise NoPayloadFoundError.
OUTPUT: payload bytes, ready for parsing
```

Alpha channels (if present) are left untouched to avoid disturbing
transparency data unnecessarily; only R, G, B channels carry payload bits.

## 12. Encryption Method

**Algorithm:** AES-256-GCM (Galois/Counter Mode), an authenticated
encryption cipher providing both confidentiality and built-in integrity —
any tampering with the ciphertext causes decryption to fail rather than
silently returning corrupted plaintext.

**Key derivation:** PBKDF2-HMAC-SHA256 with 390,000 iterations derives a
256-bit key from the user's password and a random 16-byte salt. The salt
and a random 12-byte nonce are generated fresh for every encryption
operation and stored (unencrypted) inside the payload itself — this is
safe and standard practice, since a salt/nonce is not a secret; only the
password is.

**Never implemented from scratch:** all cryptographic primitives are
provided by the audited `cryptography` Python library; the project does not
implement AES, GCM, or PBKDF2 itself.

## 13. Embedding Algorithm (Application-Level Pipeline)

```
INPUT: secret file S, cover image C, password P
STEP 1: Read S as raw bytes; compute SHA-256(S).
STEP 2: Generate random salt (16 B) and nonce (12 B).
STEP 3: Derive AES-256 key from P + salt via PBKDF2-HMAC-SHA256.
STEP 4: Encrypt S with AES-256-GCM → ciphertext (includes 16-byte tag).
STEP 5: Build payload = MAGIC + VERSION + filename + extension + salt
        + nonce + iterations + SHA256(S) + len(ciphertext) + ciphertext.
STEP 6: Check payload size against C's usable capacity.
STEP 7: Embed payload into C via LSB substitution (see Section 11).
STEP 8: Self-validate: immediately extract from the new stego image
        and confirm the recovered payload matches exactly.
STEP 9: Persist StegoFile + FileOperation records; offer download.
OUTPUT: stego image (PNG)
```

## 14. Extraction Algorithm (Application-Level Pipeline)

```
INPUT: stego image S, password P
STEP 1: Extract raw payload bits from S (see Section 11).
STEP 2: Verify magic identifier "STG1" and version number.
STEP 3: Parse filename, extension, salt, nonce, iterations,
        stored SHA-256, and ciphertext from the payload.
STEP 4: Derive the AES-256 key from P + the parsed salt.
STEP 5: Attempt AES-256-GCM decryption. On authentication failure,
        report "Decryption failed. Invalid password or corrupted
        hidden data." without leaking internal details.
STEP 6: Compute SHA-256 of the decrypted bytes and compare to the
        hash stored in the payload → PASS or FAIL verification badge.
STEP 7: Save the recovered file and offer it for download.
OUTPUT: original file, verification status
```

## 15. Database Design

| Table | Purpose | Key Fields |
|---|---|---|
| `users` | Registered accounts | id, full_name, email, username, password_hash, created_at |
| `file_operations` | Log of every embed/extract action | id, user_id (FK), operation_type, original_filename, result_filename, status, sha256_original, sha256_result, verification, timestamp |
| `stego_files` | Metadata for each generated stego image | id, user_id (FK), filename, cover_filename, payload_size, sha256_original, created_at |
| `security_analyses` | Cached MSE/PSNR/SSIM/chi-square results | id, stego_file_id (FK), mse, psnr, ssim, chi_square, capacity_bytes, payload_bytes |

All foreign keys cascade appropriately (deleting a user removes their
operations and stego files), and passwords are never stored — only Argon2
hashes.

## 16. Security Features

- **Password hashing:** Argon2 (via `argon2-cffi`), a memory-hard,
  GPU-resistant hashing algorithm — stronger than bcrypt/PBKDF2 for this
  purpose.
- **Authenticated encryption:** AES-256-GCM detects tampering; wrong
  passwords and corrupted ciphertexts both fail cleanly.
- **CSRF protection:** Flask-WTF's `CSRFProtect` on every state-changing
  form and the capacity-calculation API.
- **Secure sessions:** HttpOnly, SameSite=Lax cookies; `SESSION_COOKIE_SECURE`
  enabled in production configuration.
- **Path traversal protection:** `secure_filename()` plus explicit
  containment checks in `file_service.safe_join`.
- **Random server-side filenames:** uploaded/generated files never keep
  user-supplied names on disk, preventing overwrite and injection attacks.
- **Magic-byte validation:** cover/stego uploads are checked for real
  PNG/BMP file signatures, not just trusted by extension.
- **Rate limiting:** a simple in-memory limiter blocks more than 5 login
  attempts per IP within 5 minutes.
- **No hard-coded secrets:** `SECRET_KEY` and other configuration are
  loaded from environment variables via `.env` (see `.env.example`).
- **Ownership checks on every download/analysis route:** a user can never
  access another user's files, even by guessing IDs (returns 403).
- **Generic error messages to users; detailed errors logged server-side
  only** — no stack traces are ever shown in the browser.

## 17. Testing

25 automated tests (pytest) across four files:

- `test_crypto.py` — encrypt/decrypt round-trip, wrong password, corrupted
  ciphertext, salt uniqueness, SHA-256 determinism.
- `test_steganography.py` — capacity calculation, embed/extract round-trip,
  insufficient-capacity rejection, no-payload detection, payload parsing.
- `test_extraction.py` — the **critical full-pipeline test**: encrypt →
  embed → extract → decrypt → verify SHA-256(original) == SHA256(recovered),
  parametrized across plain text, binary, and PDF-like content; plus a
  wrong-password-on-full-pipeline test.
- `test_security.py` — registration, weak-password rejection, duplicate
  username rejection, login success/failure, unauthorized access blocking
  on `/dashboard`, `/embed`, `/extract`, password-never-stored-in-plaintext,
  path-traversal containment, and random filename generation.

All 25 tests pass. In addition, a live HTTP-level smoke test was run
against the actual running Flask server (not just in-process unit tests),
covering registration, login, a real embed with real files, a real
download, the analysis page, a real extraction, a byte-for-byte comparison
of the recovered file against the original, wrong-password error handling,
history, and post-logout access blocking — all passed.

## 18. Results

Using the generated demo files (`sample_cover.png`, 500×500 PNG; and
`sample_secret.txt`, 442 bytes):

- Usable embedding capacity of the 500×500 cover: ~93,748 bytes
  (500 × 500 × 3 bits ÷ 8, minus the 32-bit length header).
- Payload size for the 442-byte secret (with encryption + metadata
  overhead): well under 1 KB — under 1% of available capacity.
- Extraction correctly recovered the file with SHA-256(original) ==
  SHA-256(recovered), verification badge: **PASS**.
- Wrong-password extraction attempts correctly failed with "Decryption
  failed. Invalid password or corrupted hidden data." and did not leak any
  partial data.

## 19. PSNR / MSE Evaluation

For a typical embed at low payload-to-capacity ratios (well under 10% of
available capacity, as in most real secret-file use cases), the resulting
MSE between cover and stego images is very small (each modified channel
byte shifts by at most 1), producing a PSNR typically well above 50 dB —
a level widely considered visually indistinguishable from the original in
LSB-steganography literature. The Security Analysis page computes this
per-image rather than asserting a fixed number, since actual results depend
on cover image size, content, and payload size.

## 20. Advantages

- Combines two independent security layers (concealment + encryption)
  rather than relying on either alone.
- Authenticated encryption (GCM) means tampering is detected, not silently
  accepted.
- Capacity is calculated and enforced before embedding — no silent data
  loss or corruption from an oversized payload.
- Byte-for-byte file integrity is cryptographically verified on every
  extraction (SHA-256), not just assumed.
- Modular service-layer design (`crypto_service`, `stego_service`,
  `analysis_service`) makes each piece independently testable and reusable.

## 21. Limitations

- LSB steganography is not robust against image transformations — resizing,
  re-compressing (e.g., saving as JPEG), or heavy filtering will destroy or
  corrupt the hidden payload. Only lossless PNG/BMP carriers are supported.
- Statistical steganalysis (e.g., the chi-square test implemented on the
  Security Analysis page) can, in principle, detect the *presence* of
  hidden data in some cases, even though it cannot read it without the
  encryption key.
- The SSIM implementation used here is a simplified, single-window global
  approximation (documented in `analysis_service.py`) rather than a full
  windowed SSIM as in specialized image-quality libraries — sufficient for
  this project's demonstration purposes but not a substitute for a
  production-grade image-quality library.
- Audio steganography is implemented as a clearly separated, secondary
  module supporting only uncompressed 16-bit PCM WAV files; compressed
  formats (MP3, AAC) are not supported because lossy compression destroys
  LSB data by design — this is a property of lossy codecs, not a gap in
  the implementation.
- The in-memory login rate limiter resets on server restart and does not
  scale across multiple server processes; a production deployment would
  need a shared store (e.g., Redis) for this.

## 22. Applications

- Secure exchange of sensitive documents (contracts, credentials, personal
  records) over channels where an encrypted attachment alone would draw
  attention.
- Educational demonstration of applied cryptography and steganography
  concepts for computer science / cybersecurity coursework.
- Covert-channel research and steganalysis benchmarking (the built-in
  Security Analysis tools can be used to study concealment quality).

## 23. Future Scope

- Implement full windowed SSIM using a dedicated image-quality library.
- Add adaptive/randomized bit-placement (rather than sequential LSB
  substitution) to raise resistance against statistical steganalysis.
- Support additional lossless carrier formats (e.g., TIFF) and video
  steganography.
- Move the login rate limiter to a shared backing store for multi-process
  deployments.
- Add multi-factor authentication for higher-assurance use cases.

## 24. Conclusion

This project demonstrates a complete, working secure file-sharing pipeline
that meaningfully combines authenticated encryption with LSB image
steganography, rather than treating either as a superficial add-on. Every
component — from AES-256-GCM encryption and PBKDF2 key derivation, through
LSB embedding/extraction, to SHA-256 integrity verification and a fully
functional authenticated web interface — was implemented as real, working
code and validated both by unit tests and by a live end-to-end smoke test
against the running server. The system correctly rejects oversized
payloads, correctly detects wrong passwords and corrupted data, and
recovers files byte-for-byte identical to their originals.

## 25. References

1. Provos, N., & Honeyman, P. (2003). *Hide and Seek: An Introduction to
   Steganography*. IEEE Security & Privacy.
2. NIST Special Publication 800-38D — *Recommendation for Block Cipher
   Modes of Operation: Galois/Counter Mode (GCM) and GMAC*.
3. NIST Special Publication 800-132 — *Recommendation for Password-Based
   Key Derivation*.
4. Python `cryptography` library documentation — https://cryptography.io
5. Pillow (PIL Fork) documentation — https://pillow.readthedocs.io
6. Flask documentation — https://flask.palletsprojects.com
7. Wang, Z., Bovik, A.C., et al. (2004). *Image Quality Assessment: From
   Error Visibility to Structural Similarity*. IEEE Transactions on Image
   Processing (basis for the SSIM metric).
8. Westfeld, A., & Pfitzmann, A. (1999). *Attacks on Steganographic
   Systems*. Information Hiding (basis for the chi-square steganalysis test).
