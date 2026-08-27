import os
import sys
import tempfile
import pytest
from PIL import Image

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.services import stego_service


def make_test_image(path, size=(200, 200)):
    img = Image.new("RGB", size, (100, 120, 140))
    img.save(path, format="PNG")


@pytest.fixture
def cover_image():
    fd, path = tempfile.mkstemp(suffix=".png")
    os.close(fd)
    make_test_image(path)
    yield path
    os.remove(path)


def test_capacity_calculation(cover_image):
    cap = stego_service.calculate_capacity(cover_image)
    assert cap["width"] == 200
    assert cap["height"] == 200
    assert cap["channels"] == 3
    assert cap["usable_capacity_bytes"] > 0


def test_embed_and_extract_roundtrip(cover_image):
    payload = stego_service.build_payload(
        filename="test.txt", extension="txt",
        salt=os.urandom(16), nonce=os.urandom(12), iterations=390000,
        sha256_original="a" * 64, ciphertext=b"encrypted-bytes-here",
    )
    out_fd, out_path = tempfile.mkstemp(suffix=".png")
    os.close(out_fd)
    try:
        stego_service.embed_payload_into_image(cover_image, payload, out_path)
        extracted = stego_service.extract_payload_from_image(out_path)
        assert extracted == payload
    finally:
        os.remove(out_path)


def test_insufficient_capacity_raises(cover_image):
    huge_payload = os.urandom(500_000)  # far bigger than a 200x200 image can hold
    out_fd, out_path = tempfile.mkstemp(suffix=".png")
    os.close(out_fd)
    try:
        with pytest.raises(stego_service.InsufficientCapacityError):
            stego_service.embed_payload_into_image(cover_image, huge_payload, out_path)
    finally:
        os.remove(out_path)


def test_no_payload_found_on_plain_image(cover_image):
    with pytest.raises(stego_service.NoPayloadFoundError):
        stego_service.extract_payload_from_image(cover_image)


def test_payload_parse_roundtrip():
    payload = stego_service.build_payload(
        filename="secret.pdf", extension="pdf",
        salt=os.urandom(16), nonce=os.urandom(12), iterations=390000,
        sha256_original="b" * 64, ciphertext=b"some-ciphertext-bytes",
    )
    parsed = stego_service.parse_payload(payload)
    assert parsed["filename"] == "secret.pdf"
    assert parsed["extension"] == "pdf"
    assert parsed["sha256_original"] == "b" * 64
    assert parsed["ciphertext"] == b"some-ciphertext-bytes"
