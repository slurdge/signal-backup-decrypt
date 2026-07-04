"""Round-trip: build a tiny encrypted backup exactly like libsignal's frame.rs test
(`make_encrypted`), then assert our reader recovers the frames. Also checks HMAC
rejection. No real backup file needed."""

import gzip
import hmac
import os

import pytest
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from signal_backup_decrypt.envelope import (
    MAGIC,
    BackupDecryptError,
    decrypt_backup,
    encrypt_backup,
)
from signal_backup_decrypt.frames import read_frames
from signal_backup_decrypt.keys import MessageBackupKey
from signal_backup_decrypt.proto import backup_pb2

KEY = MessageBackupKey(hmac_key=bytes(range(32)), aes_key=bytes(range(100, 132)))


def _varint(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)


def _delimited(msg) -> bytes:
    data = msg.SerializeToString()
    return _varint(len(data)) + data


def _make_encrypted(key, plaintext: bytes, *, pad_after_gzip=0) -> bytes:
    compressed = gzip.compress(plaintext) + b"\x00" * pad_after_gzip
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(compressed) + padder.finalize()
    enc = Cipher(algorithms.AES(key.aes_key), modes.CBC(iv)).encryptor()
    body = iv + enc.update(padded) + enc.finalize()
    return body + hmac.new(key.hmac_key, body, "sha256").digest()


def _sample_plaintext() -> bytes:
    info = backup_pb2.BackupInfo(version=1, backupTimeMs=1700000000000)
    frame = backup_pb2.Frame()
    frame.chat.id = 42
    frame.chat.recipientId = 7
    return _delimited(info) + _delimited(frame)


@pytest.mark.parametrize("pad_after_gzip", [0, 55])
def test_round_trip(pad_after_gzip):
    blob = _make_encrypted(KEY, _sample_plaintext(), pad_after_gzip=pad_after_gzip)
    info, frames = read_frames(decrypt_backup(blob, KEY))
    assert info.version == 1
    frames = list(frames)
    assert len(frames) == 1
    assert frames[0].WhichOneof("item") == "chat"
    assert frames[0].chat.id == 42


def test_bad_hmac_rejected():
    blob = bytearray(_make_encrypted(KEY, _sample_plaintext()))
    blob[-1] ^= 0xFF
    with pytest.raises(BackupDecryptError, match="HMAC mismatch"):
        decrypt_backup(bytes(blob), KEY)


def test_forward_secrecy_rejected():
    blob = MAGIC + _make_encrypted(KEY, _sample_plaintext())
    with pytest.raises(BackupDecryptError, match="forward secrecy"):
        decrypt_backup(blob, KEY)


def test_encrypt_backup_round_trips():
    plaintext = _sample_plaintext()
    assert decrypt_backup(encrypt_backup(plaintext, KEY), KEY) == plaintext
