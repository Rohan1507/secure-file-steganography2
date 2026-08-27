import os
import sys
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.services import crypto_service


def test_encrypt_decrypt_roundtrip():
    plaintext = b"This is a top secret message for the demo."
    password = "Str0ng!Passw0rd"

    enc = crypto_service.encrypt_data(plaintext, password)
    decrypted = crypto_service.decrypt_data(
        enc["ciphertext"], password, enc["salt"], enc["nonce"], enc["iterations"]
    )
    assert decrypted == plaintext


def test_wrong_password_fails():
    plaintext = b"Confidential data"
    enc = crypto_service.encrypt_data(plaintext, "CorrectPassword1!")

    with pytest.raises(crypto_service.DecryptionError):
        crypto_service.decrypt_data(
            enc["ciphertext"], "WrongPassword1!", enc["salt"], enc["nonce"], enc["iterations"]
        )


def test_corrupted_ciphertext_fails():
    plaintext = b"Some data to protect"
    password = "Passw0rd!123"
    enc = crypto_service.encrypt_data(plaintext, password)

    corrupted = bytearray(enc["ciphertext"])
    corrupted[0] ^= 0xFF  # flip bits to corrupt

    with pytest.raises(crypto_service.DecryptionError):
        crypto_service.decrypt_data(
            bytes(corrupted), password, enc["salt"], enc["nonce"], enc["iterations"]
        )


def test_different_salts_produce_different_keys():
    key1 = crypto_service.derive_key("samepassword", os.urandom(16))
    key2 = crypto_service.derive_key("samepassword", os.urandom(16))
    assert key1 != key2


def test_sha256_of_bytes_deterministic():
    data = b"hello world"
    assert crypto_service.sha256_of_bytes(data) == crypto_service.sha256_of_bytes(data)
    assert len(crypto_service.sha256_of_bytes(data)) == 64
