"""
audio_stego.py
===============
OPTIONAL / SECONDARY MODULE.

The image LSB pipeline (stego_service.py) is the primary, fully tested
feature of this project. This module provides a clearly separated,
best-effort LSB implementation for uncompressed WAV audio (PCM samples),
reusing the same payload format from stego_service.py.

Limitation (documented per project scope): only 16-bit PCM mono/stereo WAV
files are supported. Compressed formats (MP3) are explicitly NOT supported
because lossy compression destroys LSB-encoded data - this is a fundamental
property of lossy codecs, not an implementation gap.
"""
import wave
import struct
import numpy as np

from .stego_service import (
    MAGIC, LENGTH_HEADER_BITS, NoPayloadFoundError, InsufficientCapacityError,
    _bytes_to_bits, _bits_to_bytes,
)


def calculate_audio_capacity(wav_path: str) -> dict:
    with wave.open(wav_path, "rb") as w:
        n_frames = w.getnframes()
        n_channels = w.getnchannels()
        sampwidth = w.getsampwidth()

    if sampwidth != 2:
        raise ValueError("Only 16-bit PCM WAV files are supported for audio steganography.")

    total_samples = n_frames * n_channels
    usable_bits = total_samples - LENGTH_HEADER_BITS
    usable_bytes = max(usable_bits // 8, 0)
    return {
        "frames": n_frames,
        "channels": n_channels,
        "sample_width": sampwidth,
        "usable_capacity_bytes": usable_bytes,
    }


def embed_payload_into_wav(cover_wav_path: str, payload: bytes, output_path: str) -> dict:
    with wave.open(cover_wav_path, "rb") as w:
        params = w.getparams()
        if w.getsampwidth() != 2:
            raise ValueError("Only 16-bit PCM WAV files are supported.")
        raw = w.readframes(w.getnframes())

    samples = np.frombuffer(raw, dtype=np.int16).copy()

    length_prefix = struct.pack(">I", len(payload))
    full_bits = np.concatenate([_bytes_to_bits(length_prefix), _bytes_to_bits(payload)])

    if full_bits.size > samples.size:
        raise InsufficientCapacityError(
            "Secret file is too large for this cover audio file. Please choose a longer WAV file."
        )

    n_bits = full_bits.size
    samples[:n_bits] = (samples[:n_bits] & ~1) | full_bits.astype(np.int16)

    with wave.open(output_path, "wb") as out:
        out.setparams(params)
        out.writeframes(samples.tobytes())

    return {"bits_used": int(n_bits)}


def extract_payload_from_wav(stego_wav_path: str) -> bytes:
    with wave.open(stego_wav_path, "rb") as w:
        if w.getsampwidth() != 2:
            raise ValueError("Only 16-bit PCM WAV files are supported.")
        raw = w.readframes(w.getnframes())

    samples = np.frombuffer(raw, dtype=np.int16)
    if samples.size < LENGTH_HEADER_BITS:
        raise NoPayloadFoundError("No valid hidden data was detected.")

    length_bits = (samples[:LENGTH_HEADER_BITS] & 1).astype(np.uint8)
    payload_len = struct.unpack(">I", _bits_to_bytes(length_bits))[0]

    max_possible = (samples.size - LENGTH_HEADER_BITS) // 8
    if payload_len <= 0 or payload_len > max_possible:
        raise NoPayloadFoundError("No valid hidden data was detected.")

    start = LENGTH_HEADER_BITS
    end = start + payload_len * 8
    payload_bits = (samples[start:end] & 1).astype(np.uint8)
    payload = _bits_to_bytes(payload_bits)

    if payload[:4] != MAGIC:
        raise NoPayloadFoundError("No valid hidden data was detected.")

    return payload
