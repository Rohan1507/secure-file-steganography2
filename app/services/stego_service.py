"""
stego_service.py
=================
Real LSB (Least Significant Bit) image steganography.

PAYLOAD BINARY FORMAT (written before embedding, read back after extraction):

  MAGIC            4 bytes   b"STG1"
  VERSION          1 byte    unsigned int
  FILENAME_LEN     2 bytes   uint16 (big-endian)
  FILENAME         variable  utf-8 bytes
  EXTENSION_LEN    1 byte    uint8
  EXTENSION        variable  utf-8 bytes
  SALT             16 bytes  PBKDF2 salt
  NONCE            12 bytes  AES-GCM nonce
  ITERATIONS       4 bytes   uint32 (PBKDF2 iteration count)
  SHA256_ORIGINAL  32 bytes  SHA-256 of the ORIGINAL plaintext secret file
  CIPHERTEXT_LEN   8 bytes   uint64
  CIPHERTEXT       variable  AES-256-GCM ciphertext (includes 16-byte auth tag)

This whole structure is prefixed, at embed time, by a 32-bit big-endian
length field so the extractor knows exactly how many bits to read from the
image before trying to parse anything.

Embedding strategy: 1 bit hidden in the LSB of every color channel byte
(R, G, B - alpha channel, if present, is left untouched to preserve
transparency exactly). This is the classic, well-documented LSB scheme.
"""
import struct
import numpy as np
from PIL import Image

MAGIC = b"STG1"
VERSION = 1
LENGTH_HEADER_BITS = 32  # bits used to store the payload length before the payload itself


class StegoError(Exception):
    """Generic steganography error (bad image, no payload, capacity, etc.)."""
    pass


class InsufficientCapacityError(StegoError):
    pass


class NoPayloadFoundError(StegoError):
    pass


# --------------------------------------------------------------------------- #
# Payload construction / parsing
# --------------------------------------------------------------------------- #

def build_payload(filename: str, extension: str, salt: bytes, nonce: bytes,
                   iterations: int, sha256_original: str, ciphertext: bytes) -> bytes:
    fname_b = filename.encode("utf-8")[:65535]
    ext_b = extension.encode("utf-8")[:255]
    sha_b = bytes.fromhex(sha256_original)
    assert len(sha_b) == 32

    parts = [
        MAGIC,
        struct.pack(">B", VERSION),
        struct.pack(">H", len(fname_b)), fname_b,
        struct.pack(">B", len(ext_b)), ext_b,
        salt,
        nonce,
        struct.pack(">I", iterations),
        sha_b,
        struct.pack(">Q", len(ciphertext)), ciphertext,
    ]
    return b"".join(parts)


def parse_payload(payload: bytes) -> dict:
    if len(payload) < len(MAGIC) + 1:
        raise NoPayloadFoundError("No valid hidden data was detected.")

    offset = 0
    magic = payload[offset:offset + 4]
    offset += 4
    if magic != MAGIC:
        raise NoPayloadFoundError("No valid hidden data was detected.")

    version = payload[offset]
    offset += 1
    if version != VERSION:
        raise StegoError(f"Unsupported payload version: {version}")

    fname_len = struct.unpack(">H", payload[offset:offset + 2])[0]
    offset += 2
    filename = payload[offset:offset + fname_len].decode("utf-8", errors="replace")
    offset += fname_len

    ext_len = payload[offset]
    offset += 1
    extension = payload[offset:offset + ext_len].decode("utf-8", errors="replace")
    offset += ext_len

    salt = payload[offset:offset + 16]
    offset += 16
    nonce = payload[offset:offset + 12]
    offset += 12
    iterations = struct.unpack(">I", payload[offset:offset + 4])[0]
    offset += 4
    sha256_original = payload[offset:offset + 32].hex()
    offset += 32
    ct_len = struct.unpack(">Q", payload[offset:offset + 8])[0]
    offset += 8
    ciphertext = payload[offset:offset + ct_len]
    offset += ct_len

    if len(ciphertext) != ct_len:
        raise StegoError("Corrupted payload: ciphertext truncated.")

    return {
        "filename": filename,
        "extension": extension,
        "salt": salt,
        "nonce": nonce,
        "iterations": iterations,
        "sha256_original": sha256_original,
        "ciphertext": ciphertext,
    }


# --------------------------------------------------------------------------- #
# Bit helpers
# --------------------------------------------------------------------------- #

def _bytes_to_bits(data: bytes) -> np.ndarray:
    arr = np.frombuffer(data, dtype=np.uint8)
    return np.unpackbits(arr)


def _bits_to_bytes(bits: np.ndarray) -> bytes:
    return np.packbits(bits).tobytes()


# --------------------------------------------------------------------------- #
# Capacity
# --------------------------------------------------------------------------- #

def calculate_capacity(image_path: str) -> dict:
    """Return capacity info (in bytes) for a cover image, using 1 LSB per RGB channel."""
    with Image.open(image_path) as img:
        img = img.convert("RGB") if img.mode not in ("RGB", "RGBA") else img
        width, height = img.size
        channels = 3  # we only ever use R, G, B - alpha is preserved untouched

    total_bits = width * height * channels
    usable_bits = total_bits - LENGTH_HEADER_BITS
    usable_bytes = max(usable_bits // 8, 0)

    return {
        "width": width,
        "height": height,
        "channels": channels,
        "total_capacity_bits": total_bits,
        "total_capacity_bytes": total_bits // 8,
        "usable_capacity_bytes": usable_bytes,
    }


# --------------------------------------------------------------------------- #
# Embedding
# --------------------------------------------------------------------------- #

def embed_payload_into_image(cover_path: str, payload: bytes, output_path: str) -> dict:
    """
    Embed `payload` bytes into the cover image at `cover_path` using LSB
    substitution, and save the result as PNG to `output_path`.
    """
    with Image.open(cover_path) as img:
        has_alpha = img.mode == "RGBA"
        img = img.convert("RGBA") if has_alpha else img.convert("RGB")
        arr = np.array(img)  # shape (H, W, 3) or (H, W, 4)

    height, width = arr.shape[0], arr.shape[1]
    rgb = arr[:, :, :3]

    capacity_bits = height * width * 3
    length_prefix = struct.pack(">I", len(payload))
    full_bits = np.concatenate([_bytes_to_bits(length_prefix), _bytes_to_bits(payload)])

    if full_bits.size > capacity_bits:
        needed_bytes = (full_bits.size + 7) // 8
        raise InsufficientCapacityError(
            "Secret file is too large for this cover image. Please select a larger image. "
            f"(needed ~{needed_bytes} bytes of capacity, image provides "
            f"{capacity_bits // 8} bytes)"
        )

    flat = rgb.reshape(-1)  # flatten R,G,B,R,G,B,...
    flat = flat.copy()
    n_bits = full_bits.size
    # Clear LSB then set to payload bit
    flat[:n_bits] = (flat[:n_bits] & 0xFE) | full_bits.astype(np.uint8)

    new_rgb = flat.reshape(rgb.shape)
    if has_alpha:
        arr[:, :, :3] = new_rgb
        out_img = Image.fromarray(arr, mode="RGBA")
    else:
        out_img = Image.fromarray(new_rgb, mode="RGB")

    out_img.save(output_path, format="PNG")

    return {
        "width": width,
        "height": height,
        "bits_used": int(n_bits),
        "bytes_used": int((n_bits + 7) // 8),
        "capacity_bits": int(capacity_bits),
    }


# --------------------------------------------------------------------------- #
# Extraction
# --------------------------------------------------------------------------- #

def extract_payload_from_image(stego_path: str) -> bytes:
    """Read the embedded payload bytes back out of a stego image."""
    with Image.open(stego_path) as img:
        img = img.convert("RGBA") if img.mode == "RGBA" else img.convert("RGB")
        arr = np.array(img)

    rgb = arr[:, :, :3]
    flat = rgb.reshape(-1)

    if flat.size < LENGTH_HEADER_BITS:
        raise NoPayloadFoundError("No valid hidden data was detected.")

    length_bits = flat[:LENGTH_HEADER_BITS] & 1
    payload_len = struct.unpack(">I", _bits_to_bytes(length_bits))[0]

    # Sanity check against a very large / implausible length before we try to slice
    max_possible_bytes = (flat.size - LENGTH_HEADER_BITS) // 8
    if payload_len <= 0 or payload_len > max_possible_bytes:
        raise NoPayloadFoundError("No valid hidden data was detected.")

    start = LENGTH_HEADER_BITS
    end = start + payload_len * 8
    payload_bits = flat[start:end] & 1
    payload = _bits_to_bytes(payload_bits)

    if payload[:4] != MAGIC:
        raise NoPayloadFoundError("No valid hidden data was detected.")

    return payload


def validate_extraction_roundtrip(cover_path: str, payload: bytes) -> bool:
    """Embed into a temp copy and immediately extract, to self-validate the pipeline."""
    import tempfile, os as _os
    with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tmp:
        tmp_path = tmp.name
    try:
        embed_payload_into_image(cover_path, payload, tmp_path)
        extracted = extract_payload_from_image(tmp_path)
        return extracted == payload
    finally:
        if _os.path.exists(tmp_path):
            _os.remove(tmp_path)
