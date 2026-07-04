"""Local-archive metadata parsing + BackupId recovery (AES-256-CTR) round-trip.

Proves we can recover the 16-byte BackupId from the `metadata` file using only the AEP
(via the local metadata key), and that change-key's rekeying round-trips.
"""

import os

import pytest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from signal_backup_decrypt.envelope import BackupDecryptError, decrypt_backup, encrypt_backup
from signal_backup_decrypt.keys import (
    derive_backup_key,
    derive_local_backup_metadata_key,
    derive_message_backup_key,
    generate_aep,
)
from signal_backup_decrypt.local import (
    _parse_metadata,
    build_metadata,
    message_key_for_snapshot,
    recover_backup_id,
    rekey_snapshot,
)

AEP = "dtjs858asj6tv0jzsqrsmj0ubp335pisj98e9ssnss8myoc08drhtcktyawvx45l"


def _build_metadata(iv: bytes, ct: bytes) -> bytes:
    # EncryptedBackupId { 1: bytes iv, 2: bytes encryptedId }
    sub = b"\x0a" + bytes([len(iv)]) + iv + b"\x12" + bytes([len(ct)]) + ct
    # Metadata { 1: uint version = 1, 2: EncryptedBackupId }
    return b"\x08\x01\x12" + bytes([len(sub)]) + sub


def test_recover_backup_id():
    backup_key = derive_backup_key(AEP)
    metadata_key = derive_local_backup_metadata_key(backup_key)

    backup_id = bytes(range(16))
    iv = os.urandom(12)  # Aes256Ctr32 uses a 12-byte nonce
    enc = Cipher(algorithms.AES(metadata_key), modes.CTR(iv + b"\x00\x00\x00\x00")).encryptor()
    ct = enc.update(backup_id) + enc.finalize()

    metadata = _build_metadata(iv, ct)
    assert _parse_metadata(metadata) == (iv, ct)
    assert recover_backup_id(metadata, backup_key) == backup_id


def test_build_metadata_round_trips():
    backup_key = derive_backup_key(AEP)
    backup_id = os.urandom(16)
    assert recover_backup_id(build_metadata(backup_id, backup_key), backup_key) == backup_id


def test_rekey_snapshot(tmp_path):
    plaintext = b"not really a frame stream, but the envelope doesn't care"
    snapshot = tmp_path / "signal-backup-1"
    snapshot.mkdir()
    backup_key = derive_backup_key(AEP)
    backup_id = os.urandom(16)
    (snapshot / "metadata").write_bytes(build_metadata(backup_id, backup_key))
    (snapshot / "main").write_bytes(
        encrypt_backup(plaintext, derive_message_backup_key(backup_key, backup_id))
    )

    new_aep = generate_aep()
    out = tmp_path / "signal-backup-1-rekeyed"
    rekey_snapshot(snapshot, AEP, new_aep, out)

    rekeyed = (out / "main").read_bytes()
    assert decrypt_backup(rekeyed, message_key_for_snapshot(out, new_aep)) == plaintext
    with pytest.raises(BackupDecryptError):  # old key must no longer open it
        decrypt_backup(rekeyed, message_key_for_snapshot(out, AEP))
