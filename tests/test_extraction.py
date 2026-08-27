"""
Critical end-to-end test for the whole project:

    Original File -> Encrypt -> Embed -> Extract -> Decrypt -> Recovered File

Then verify SHA256(original) == SHA256(recovered). This test MUST pass.
"""
import os
import sys
import tempfile
import pytest
from PIL import Image

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.services import crypto_service, stego_service


def make_test_image(path, size=(300, 300)):
    img = Image.new("RGB", size, (60, 90, 120))
    img.save(path, format="PNG")


@pytest.fixture
def cover_image():
    fd, path = tempfile.mkstemp(suffix=".png")
    os.close(fd)
    make_test_image(path)
    yield path
    os.remove(path)


@pytest.mark.parametrize("secret_content,filename,extension", [
    (b"Plain text secret content for the demo.", "note.txt", "txt"),
    (bytes(range(256)) * 10, "binary_blob.bin", "bin"),
    (b"%PDF-1.4 fake pdf header bytes for testing purposes only", "doc.pdf", "pdf"),
])
def test_full_pipeline_roundtrip(cover_image, secret_content, filename, extension):
    password = "SuperSecure!Pass1"

    # STEP 1: hash original
    sha_original = crypto_service.sha256_of_bytes(secret_content)

    # STEP 2: encrypt
    enc = crypto_service.encrypt_data(secret_content, password)

    # STEP 3: build payload
    payload = stego_service.build_payload(
        filename=filename, extension=extension,
        salt=enc["salt"], nonce=enc["nonce"], iterations=enc["iterations"],
        sha256_original=sha_original, ciphertext=enc["ciphertext"],
    )

    # STEP 4: embed
    out_fd, stego_path = tempfile.mkstemp(suffix=".png")
    os.close(out_fd)
    try:
        stego_service.embed_payload_into_image(cover_image, payload, stego_path)

        # STEP 5: extract
        extracted_payload = stego_service.extract_payload_from_image(stego_path)
        parsed = stego_service.parse_payload(extracted_payload)

        # STEP 6: decrypt
        recovered = crypto_service.decrypt_data(
            parsed["ciphertext"], password, parsed["salt"], parsed["nonce"], parsed["iterations"]
        )

        # STEP 7: verify
        sha_recovered = crypto_service.sha256_of_bytes(recovered)
        assert sha_recovered == sha_original
        assert recovered == secret_content
        assert parsed["filename"] == filename
        assert parsed["extension"] == extension
    finally:
        os.remove(stego_path)


def test_wrong_password_on_full_pipeline(cover_image):
    secret_content = b"data that should stay hidden"
    enc = crypto_service.encrypt_data(secret_content, "CorrectPassword1!")
    sha_original = crypto_service.sha256_of_bytes(secret_content)

    payload = stego_service.build_payload(
        filename="secret.txt", extension="txt",
        salt=enc["salt"], nonce=enc["nonce"], iterations=enc["iterations"],
        sha256_original=sha_original, ciphertext=enc["ciphertext"],
    )

    out_fd, stego_path = tempfile.mkstemp(suffix=".png")
    os.close(out_fd)
    try:
        stego_service.embed_payload_into_image(cover_image, payload, stego_path)
        extracted_payload = stego_service.extract_payload_from_image(stego_path)
        parsed = stego_service.parse_payload(extracted_payload)

        with pytest.raises(crypto_service.DecryptionError):
            crypto_service.decrypt_data(
                parsed["ciphertext"], "WrongPassword!", parsed["salt"],
                parsed["nonce"], parsed["iterations"]
            )
    finally:
        os.remove(stego_path)
