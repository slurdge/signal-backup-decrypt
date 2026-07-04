"""Support for the folder-based *local* archive format (snapshot directory).

Layout (Signal-Android backup/v2/local/LocalArchiver.kt):
    <snapshot>/metadata   - tiny proto: version + BackupId encrypted with the local metadata key
    <snapshot>/main       - the encrypted message backup (same envelope as envelope.py)
    <snapshot>/files      - index of media file names (media bytes live outside, keyed separately)

The metadata key is derived from the BackupKey alone (no ACI), so we recover the BackupId
from `metadata` and never need the account UUID for a local archive.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .envelope import BackupDecryptError, decrypt_backup, encrypt_backup
from .frames import read_varint
from .keys import (
    MessageBackupKey,
    derive_backup_key,
    derive_local_backup_metadata_key,
    derive_message_backup_key,
)


def is_snapshot(path: Path) -> bool:
    return (path / "main").is_file() and (path / "metadata").is_file()


def find_snapshot(path: Path) -> Path:
    """Resolve `path` to a snapshot dir (has main+metadata), searching one level down."""
    if is_snapshot(path):
        return path
    candidates = [d for d in sorted(path.iterdir()) if d.is_dir() and is_snapshot(d)]
    if not candidates:
        raise BackupDecryptError(
            f"no local snapshot (a folder with 'main' and 'metadata') found under {path}"
        )
    return max(candidates, key=lambda d: d.name)  # names are timestamped; newest wins


def _proto_fields(data: bytes) -> Iterator[tuple[int, object]]:
    """Minimal protobuf wire reader: yields (field_number, value) for the metadata proto."""
    pos = 0
    while pos < len(data):
        tag, pos = read_varint(data, pos)
        field, wire = tag >> 3, tag & 0x7
        if wire == 0:  # varint
            value, pos = read_varint(data, pos)
        elif wire == 2:  # length-delimited (bytes / sub-message)
            length, pos = read_varint(data, pos)
            value, pos = data[pos : pos + length], pos + length
        elif wire == 5:  # 32-bit
            value, pos = data[pos : pos + 4], pos + 4
        elif wire == 1:  # 64-bit
            value, pos = data[pos : pos + 8], pos + 8
        else:
            raise BackupDecryptError(f"unexpected protobuf wire type {wire} in metadata")
        yield field, value


def _parse_metadata(data: bytes) -> tuple[bytes, bytes]:
    """Return (iv, encrypted_backup_id) from the metadata proto (fields: 1=version, 2=EncryptedBackupId{1=iv,2=id})."""
    iv = ct = None
    for field, value in _proto_fields(data):
        if field == 2 and isinstance(value, (bytes, bytearray)):
            for f2, v2 in _proto_fields(value):
                if f2 == 1:
                    iv = bytes(v2)
                elif f2 == 2:
                    ct = bytes(v2)
    if iv is None or ct is None:
        raise BackupDecryptError("metadata file is missing the encrypted backup id")
    return iv, ct


def recover_backup_id(metadata_bytes: bytes, backup_key: bytes) -> bytes:
    """Decrypt the 16-byte BackupId from the metadata (AES-256-CTR, 12-byte nonce + 32-bit counter)."""
    iv, ct = _parse_metadata(metadata_bytes)
    if len(iv) == 12:
        counter = iv + b"\x00\x00\x00\x00"  # Aes256Ctr32: 96-bit nonce, 32-bit counter starting at 0
    elif len(iv) == 16:
        counter = iv
    else:
        raise BackupDecryptError(f"unexpected metadata IV length {len(iv)}")
    metadata_key = derive_local_backup_metadata_key(backup_key)
    decryptor = Cipher(algorithms.AES(metadata_key), modes.CTR(counter)).decryptor()
    return decryptor.update(ct) + decryptor.finalize()


def message_key_for_snapshot(snapshot_dir: Path, aep: str) -> MessageBackupKey:
    """Derive the MessageBackupKey for a local snapshot from the AEP alone (no ACI)."""
    backup_key = derive_backup_key(aep)
    backup_id = recover_backup_id((snapshot_dir / "metadata").read_bytes(), backup_key)
    return derive_message_backup_key(backup_key, backup_id)  # local main is the legacy (no-FS) envelope


def _varint(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)


def _metadata_version(data: bytes) -> int:
    for field, value in _proto_fields(data):
        if field == 1 and isinstance(value, int):
            return value
    return 1


def build_metadata(backup_id: bytes, backup_key: bytes, version: int = 1) -> bytes:
    """Encrypt the BackupId and serialize the metadata proto (inverse of recover_backup_id)."""
    iv = os.urandom(12)  # Aes256Ctr32: 96-bit nonce, 32-bit counter starting at 0
    metadata_key = derive_local_backup_metadata_key(backup_key)
    encryptor = Cipher(algorithms.AES(metadata_key), modes.CTR(iv + b"\x00\x00\x00\x00")).encryptor()
    ct = encryptor.update(backup_id) + encryptor.finalize()
    # EncryptedBackupId { 1: bytes iv, 2: bytes encryptedId }
    sub = b"\x0a" + _varint(len(iv)) + iv + b"\x12" + _varint(len(ct)) + ct
    # Metadata { 1: uint version, 2: EncryptedBackupId }
    return b"\x08" + _varint(version) + b"\x12" + _varint(len(sub)) + sub


def rekey_snapshot(snapshot_dir: Path, old_aep: str, new_aep: str, out_dir: Path) -> None:
    """Re-encrypt a snapshot's `metadata` + `main` under a new AEP, writing them to out_dir.

    A fresh random BackupId is generated too, severing any link to the account the old one
    was derived from. Media needs no rewrite: each attachment's key is stored inside `main`,
    not derived from the AEP, so the rekeyed snapshot keeps using the shared `files/` tree.
    (The snapshot's `files` name-index is not carried over; nothing here reads it.)
    """
    metadata = (snapshot_dir / "metadata").read_bytes()
    old_key = message_key_for_snapshot(snapshot_dir, old_aep)
    plaintext = decrypt_backup((snapshot_dir / "main").read_bytes(), old_key)

    new_backup_key = derive_backup_key(new_aep)
    new_backup_id = os.urandom(16)
    new_key = derive_message_backup_key(new_backup_key, new_backup_id)

    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "metadata").write_bytes(
        build_metadata(new_backup_id, new_backup_key, _metadata_version(metadata))
    )
    (out_dir / "main").write_bytes(encrypt_backup(plaintext, new_key))
