"""Decrypt the v2 backup envelope down to the plaintext frame stream.

Layout (message-backup/src/frame.rs):
    IV(16) || AES-256-CBC(aes_key, IV, plaintext) || HMAC-SHA256(hmac_key)(32)

The HMAC covers IV||ciphertext. The CBC plaintext is a gzip stream (PKCS7-padded,
possibly with trailing padding after the gzip EOF); we decompress with a streaming
inflater that stops at the gzip end marker, so the padding never matters.

Files that start with the "SBACKUP\\x01" magic use forward secrecy (the salt lives in
Signal's online SVRB, not derivable offline) and are rejected — local archives don't
use it.
"""

from __future__ import annotations

import gzip
import hmac
import os
import zlib

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .keys import MessageBackupKey

MAGIC = b"SBACKUP\x01"
HMAC_LEN = 32
IV_LEN = 16
_GZIP_WBITS = 31  # zlib gzip mode (window 15 + 16), stops at the gzip stream end


class BackupDecryptError(Exception):
    pass


def has_forward_secrecy(data: bytes) -> bool:
    """True if the file starts with the forward-secrecy magic number."""
    return data[: len(MAGIC)] == MAGIC


def decrypt_backup(data: bytes, key: MessageBackupKey) -> bytes:
    """Verify the HMAC, decrypt, and decompress; return the plaintext frame stream."""
    if has_forward_secrecy(data):
        raise BackupDecryptError("backup uses forward secrecy (SBACKUP magic) — unsupported")
    if len(data) < IV_LEN + HMAC_LEN:
        raise BackupDecryptError("file too short to be an encrypted backup")

    content, expected_mac = data[:-HMAC_LEN], data[-HMAC_LEN:]
    actual_mac = hmac.new(key.hmac_key, content, "sha256").digest()
    if not hmac.compare_digest(actual_mac, expected_mac):
        raise BackupDecryptError("HMAC mismatch — wrong AEP or corrupt file")

    iv, ciphertext = content[:IV_LEN], content[IV_LEN:]
    if len(ciphertext) == 0 or len(ciphertext) % IV_LEN != 0:
        raise BackupDecryptError("ciphertext is not a whole number of AES blocks")

    decryptor = Cipher(algorithms.AES(key.aes_key), modes.CBC(iv)).decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()

    inflater = zlib.decompressobj(wbits=_GZIP_WBITS)
    plaintext = inflater.decompress(padded)
    plaintext += inflater.flush()  # ponytail: whole plaintext in memory; ok since v2 message
    return plaintext                #           backups hold text+metadata only (media is separate).


def encrypt_backup(plaintext: bytes, key: MessageBackupKey) -> bytes:
    """Inverse of decrypt_backup: gzip, PKCS7-pad, encrypt with a fresh IV, append the HMAC."""
    padder = padding.PKCS7(128).padder()
    padded = padder.update(gzip.compress(plaintext)) + padder.finalize()
    iv = os.urandom(IV_LEN)
    encryptor = Cipher(algorithms.AES(key.aes_key), modes.CBC(iv)).encryptor()
    content = iv + encryptor.update(padded) + encryptor.finalize()
    return content + hmac.new(key.hmac_key, content, "sha256").digest()
