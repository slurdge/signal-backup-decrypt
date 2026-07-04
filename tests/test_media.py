"""Attachment media: encrypt like AttachmentCipherOutputStream, then decrypt + locate."""

import hashlib
import hmac
import os

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from signal_backup_decrypt.media import MediaExtractor, media_name
from signal_backup_decrypt.proto import backup_pb2

CONTENT = b"\xff\xd8\xff pretend-jpeg-bytes " * 10  # arbitrary binary content


def _encrypt(local_key: bytes, plaintext: bytes) -> bytes:
    aes_key, mac_key = local_key[:32], local_key[32:]
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    enc = Cipher(algorithms.AES(aes_key), modes.CBC(iv)).encryptor()
    body = iv + enc.update(padded) + enc.finalize()
    return body + hmac.new(mac_key, body, "sha256").digest()


def _pointer(local_key, plaintext_hash, size):
    p = backup_pb2.FilePointer(contentType="image/jpeg", fileName="pic.jpg")
    p.locatorInfo.localKey = local_key
    p.locatorInfo.plaintextHash = plaintext_hash
    p.locatorInfo.size = size
    return p


def test_media_round_trip(tmp_path):
    local_key = os.urandom(64)
    plaintext_hash = hashlib.sha256(CONTENT).digest()
    name = media_name(plaintext_hash, local_key)

    files_dir = tmp_path / "files"
    (files_dir / name[:2]).mkdir(parents=True)
    (files_dir / name[:2] / name).write_bytes(_encrypt(local_key, CONTENT))

    ex = MediaExtractor(files_dir, tmp_path / "out" / "media")
    result = ex.extract(_pointer(local_key, plaintext_hash, len(CONTENT)))

    assert result is not None and result["kind"] == "image"
    written = (tmp_path / "out" / "media" / result["src"].split("/")[-1]).read_bytes()
    assert written == CONTENT
    assert ex.decrypted == 1
    # second call is cached, not re-decrypted
    ex.extract(_pointer(local_key, plaintext_hash, len(CONTENT)))
    assert ex.decrypted == 1


def test_media_absent_when_no_local_key(tmp_path):
    ex = MediaExtractor(tmp_path / "files", tmp_path / "out")
    assert ex.extract(backup_pb2.FilePointer(contentType="image/jpeg")) is None
