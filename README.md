# Secure File Sharing with Steganography

An academic project implementing a secure file-sharing pipeline that
**encrypts** a secret file with AES-256-GCM and then **hides** it inside a
cover image using LSB (Least Significant Bit) steganography, so the data
travels invisibly and only someone with the correct password can recover it.

```
SECRET FILE → ENCRYPTION (AES-256-GCM) → ENCRYPTED PAYLOAD → LSB EMBEDDING
→ STEGO IMAGE → SECURE TRANSFER → LSB EXTRACTION → INTEGRITY VERIFICATION
→ DECRYPTION → ORIGINAL FILE
```

---

## 1. Objective

Steganography hides the *existence* of a message; encryption scrambles a
message but still reveals that a secret exists. This project combines both:
your file is encrypted first, then the ciphertext is hidden inside an
ordinary-looking PNG/BMP image. An observer has to notice the hidden channel
**and then** break AES-256-GCM to read anything.

## 2. Problem Statement

Sharing sensitive files over normal channels (email, chat, cloud storage)
draws attention to the fact that something confidential is being
transmitted, and relying on encryption alone still broadcasts "this is a
secret." A system is needed that both conceals the existence of the data
and protects its content if discovered.

## 3. Features

- Full authentication system (register, login, logout) with Argon2 password
  hashing, secure sessions, and login rate limiting.
- AES-256-GCM authenticated encryption (confidentiality + integrity) with a
  PBKDF2-HMAC-SHA256 key derived from a user-chosen password.
- Real LSB steganography over PNG/BMP images (1 bit per RGB channel byte).
- Structured, versioned binary payload format carrying filename, extension,
  salt, nonce, iteration count, SHA-256 hash, and ciphertext.
- Live capacity calculation before embedding, with a clear error if the
  secret is too large for the chosen cover image — no silent truncation.
- Extraction with automatic detection of missing/invalid payloads, clear
  "wrong password" vs "no hidden data" error messages, and SHA-256
  verification (PASS/FAIL) against the original file.
- Security Analysis page: MSE, PSNR, a simplified global SSIM, and an
  educational chi-square LSB steganalysis statistic, plus a cover/stego/
  difference-image visual comparison.
- Per-user dashboard, full operation history, and downloadable results.
- Optional secondary module: WAV (16-bit PCM) audio steganography, using
  the same payload format and pipeline.
- Secure upload handling: random server-side filenames, extension
  allow-listing, magic-byte validation, path-traversal protection.
- CSRF protection, security response headers, and no plaintext secrets ever
  written to disk (secret files are processed in memory).

## 4. Technology Stack

| Layer          | Technology |
|----------------|------------|
| Backend        | Python 3, Flask |
| Database       | SQLite + SQLAlchemy (Flask-SQLAlchemy) |
| Auth           | Flask-Login, Argon2 (argon2-cffi) |
| Forms/CSRF     | Flask-WTF |
| Cryptography   | `cryptography` library — AES-256-GCM, PBKDF2-HMAC-SHA256 |
| Image handling | Pillow, NumPy |
| Analysis       | NumPy, SciPy (chi-square test) |
| Frontend       | HTML5, custom CSS (dark cybersecurity theme), vanilla JS |

No custom cryptography was implemented — all encryption uses the
industry-standard `cryptography` library's AEAD primitives.

## 5. System Architecture

```
secure-file-steganography/
├── app/
│   ├── __init__.py            # App factory, blueprints, security headers
│   ├── models.py               # User, FileOperation, StegoFile, SecurityAnalysis
│   ├── routes/
│   │   ├── auth.py             # register / login / logout
│   │   ├── dashboard.py        # landing, dashboard, history, help
│   │   ├── steganography.py    # embed / extract / capacity API / downloads
│   │   └── analysis.py         # security analysis page + image serving
│   ├── services/
│   │   ├── crypto_service.py   # AES-256-GCM encrypt/decrypt, PBKDF2, SHA-256
│   │   ├── stego_service.py    # payload format, LSB embed/extract, capacity
│   │   ├── audio_stego.py      # optional WAV LSB module
│   │   ├── file_service.py     # safe filenames, path-traversal protection
│   │   └── analysis_service.py # MSE / PSNR / SSIM / chi-square / diff image
│   ├── templates/               # Jinja2 templates (dark cybersecurity theme)
│   └── static/{css,js}/
├── uploads/                     # temporary uploaded cover/stego images
├── generated/                   # generated stego images, recovered files, diffs
├── tests/                       # pytest test suite (25 tests)
├── demo_files/                  # created by create_demo_files.py
├── config.py
├── run.py
├── requirements.txt
├── .env.example
└── create_demo_files.py
```

## 6. How LSB Steganography Works

Every pixel channel (Red, Green, Blue) is a byte, 0–255. The least
significant bit is the right-most bit of that byte — flipping it changes the
value by at most 1, which is invisible to the human eye. By replacing the
LSB of many pixel channel bytes with the bits of a secret payload, a large
amount of data can be hidden across an image's millions of pixels without
visibly altering it. This project uses 1 bit per R/G/B channel (alpha, if
present, is left untouched to preserve transparency), giving a capacity of
roughly `width × height × 3` bits per image.

## 7. How Encryption Works

1. A 256-bit AES key is derived from the user's password and a random
   16-byte salt using **PBKDF2-HMAC-SHA256** (390,000 iterations).
2. The secret file's raw bytes are encrypted with **AES-256-GCM** using a
   random 12-byte nonce. GCM is an authenticated encryption mode: it
   produces both ciphertext and a 16-byte authentication tag, so any
   tampering or wrong password causes decryption to fail cleanly rather
   than silently returning garbage.
3. Salt, nonce, iteration count, and a SHA-256 hash of the *original*
   plaintext are stored alongside the ciphertext in the payload, so the
   receiver's app has everything needed to decrypt and verify — except the
   password, which is never stored or transmitted.

## 8. Payload Format

```
MAGIC            4 bytes   b"STG1"
VERSION          1 byte
FILENAME_LEN     2 bytes   (uint16, big-endian)
FILENAME         variable  (UTF-8)
EXTENSION_LEN    1 byte
EXTENSION        variable  (UTF-8)
SALT             16 bytes  (PBKDF2 salt)
NONCE            12 bytes  (AES-GCM nonce)
ITERATIONS       4 bytes   (uint32)
SHA256_ORIGINAL  32 bytes  (hash of the original plaintext)
CIPHERTEXT_LEN   8 bytes   (uint64)
CIPHERTEXT       variable  (AES-256-GCM ciphertext + auth tag)
```

At embed time this whole structure is prefixed with a 32-bit length field
so the extractor knows exactly how many bits to read before parsing.

## 9. Installation

### Prerequisites
- Python 3.10+
- pip

### Windows

```cmd
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env
python run.py
```

### Linux / macOS

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
python run.py
```

Then open **http://127.0.0.1:5000** in your browser.

### Environment variables

Edit `.env` (copied from `.env.example`) and set a real `SECRET_KEY`:

```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

Paste the output as `SECRET_KEY=...` in `.env`.

### Database initialization

No manual step needed — `db.create_all()` runs automatically on first
startup and creates `stego_app.db` (SQLite) in the project root.

## 10. Generating Demo Files

To test the full workflow immediately:

```bash
python create_demo_files.py
```

This creates `demo_files/sample_cover.png` (500×500, ~93 KB usable capacity)
and `demo_files/sample_secret.txt` (a small text file), ready to use on the
Embed page.

## 11. Running the Tests

```bash
pip install pytest
pytest tests/ -v
```

The suite includes 25 tests covering encryption/decryption, wrong-password
handling, LSB embed/extract round-trips, capacity validation, the full
encrypt→embed→extract→decrypt→verify pipeline (parametrized across text,
binary, and PDF-like content), authentication, and unauthorized-access
protection. All 25 currently pass.

The **critical test** (`tests/test_extraction.py`) runs:

```
Original File → Encrypt → Embed → Extract → Decrypt → Recovered File
```

and asserts `SHA256(original) == SHA256(recovered)`.

## 12. Using the Application

1. **Register** an account (strong password required: 8+ chars, upper,
   lower, number, special character).
2. **Login**.
3. On the **Embed** page: select a PNG/BMP cover image, select any secret
   file, watch the live capacity meter, set an encryption password, and
   click **Embed Secret File**. Download the resulting stego image.
4. On the **Extract** page: upload the stego image, enter the same
   password, and click **Extract Secret File**. The app shows the original
   vs. extracted SHA-256 hashes and a PASS/FAIL verification badge, with a
   download link for the recovered file.
5. Visit **Security Analysis** from the embed result to see MSE, PSNR,
   SSIM, chi-square, and a visual cover/stego/difference comparison.
6. **History** shows every operation you've performed.

## 13. Security Considerations

- Passwords are hashed with **Argon2**, never stored in plaintext.
- Encryption keys are never hard-coded; they're derived per-file from a
  user-supplied password via PBKDF2.
- Secret files are processed **in memory** and never written to disk in
  plaintext form — only the encrypted, embedded stego image and (after
  extraction, with correct password) the recovered file touch disk.
- Uploaded files get random server-side filenames; the original filename
  is never trusted for filesystem paths (path-traversal protection via
  `secure_filename` + containment checks).
- Cover/stego images are validated by magic bytes, not just extension.
- CSRF protection is enabled on all state-changing forms.
- Security response headers (`X-Content-Type-Options`,
  `X-Frame-Options`, etc.) are set on every response.
- Login attempts are rate-limited (5 attempts / 5 minutes per IP).
- Stack traces are never shown to users; errors are logged server-side and
  a generic message is shown instead.

## 14. Evaluation Methodology

The **Security Analysis** page quantifies how much the stego image differs
from the cover image:

- **MSE** (Mean Squared Error) — average squared pixel difference.
- **PSNR** (Peak Signal-to-Noise Ratio) — `10·log10(255² / MSE)`; higher
  generally means less visible distortion.
- **SSIM** — a simplified, single-window structural similarity score
  (0–1, 1 = identical); a full windowed SSIM (as in scikit-image) is more
  precise but was simplified here to avoid an extra heavy dependency.
- **Chi-square LSB test** — a classic, educational steganalysis statistic
  comparing observed vs. expected histogram pair frequencies. Lower
  statistical deviation generally indicates better concealment, but **no
  steganographic method is guaranteed to evade steganalysis** — this
  project makes no claim of being undetectable.

## 15. Limitations

- Only **PNG and BMP** are supported as cover/stego image formats — JPEG's
  lossy compression would destroy the embedded LSB data.
- Audio steganography only supports **16-bit PCM WAV** files, not
  compressed formats like MP3, for the same reason.
- SSIM is a simplified global calculation, not a full sliding-window
  implementation.
- The chi-square test is educational, not a production-grade steganalysis
  detector.
- This is a single-instance SQLite deployment intended for local/academic
  demonstration, not a scaled production service.

## 16. Future Enhancements

- Support additional lossless carrier formats (e.g., TIFF).
- Windowed, multi-scale SSIM for more accurate quality scoring.
- Adaptive/randomized bit placement (rather than sequential LSB) to
  improve resistance to statistical steganalysis.
- Multi-factor authentication.
- Cloud storage integration for stego image sharing.

## 17. License

See `LICENSE`. Provided for educational use.
