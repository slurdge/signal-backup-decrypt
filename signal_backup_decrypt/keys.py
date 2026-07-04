"""Derive the message-backup encryption keys for a new-format (v2) Signal backup.

Transcribed from libsignal (vendor/libsignal, pinned commit):
  - account-keys/src/backup.rs : BackupKey / local metadata key derivation
  - message-backup/src/key.rs  : MessageBackupKey derivation

Whole chain is HKDF-SHA256. See the README for the diagram.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

AEP_LEN = 64  # Account Entropy Pool: 64 ASCII chars, used verbatim as HKDF input keying material.
_AEP_ALPHABET = (
    "abcdefghijklmnopqrstuvwxyz0123456789"  # AccountEntropyPool: lowercase + digits
)

_BACKUP_KEY_INFO = b"20240801_SIGNAL_BACKUP_KEY"
_LOCAL_METADATA_KEY_INFO = b"20241011_SIGNAL_LOCAL_BACKUP_METADATA_KEY"
_MSG_DST = b"20241007_SIGNAL_BACKUP_ENCRYPT_MESSAGE_BACKUP:"


# Signal swaps visually-ambiguous characters for display (AccountEntropyPool.CHARACTER_DISPLAY_MAP):
# storage 'O' <-> display '#', storage '0' <-> display '='. Reverse it before deriving.
_DISPLAY_TO_STORAGE = str.maketrans({"#": "O", "=": "0"})
_STORAGE_TO_DISPLAY = str.maketrans({"O": "#", "0": "="})


def normalize_aep(aep: str) -> str:
    """Turn a user-pasted recovery key (grouped, uppercased, display-swapped) into the canonical AEP."""
    return "".join(aep.split()).translate(_DISPLAY_TO_STORAGE).lower()


def display_aep(aep: str) -> str:
    """Format a canonical AEP the way Signal displays it: uppercase, O->#/0->=, groups of 4."""
    s = aep.upper().translate(_STORAGE_TO_DISPLAY)
    return " ".join(s[i : i + 4] for i in range(0, len(s), 4))


def generate_aep() -> str:
    """Generate a fresh random Account Entropy Pool, same format as the app's."""
    return "".join(secrets.choice(_AEP_ALPHABET) for _ in range(AEP_LEN))


def _hkdf(ikm: bytes, length: int, info: bytes, salt: bytes | None = None) -> bytes:
    # cryptography's HKDF == RFC 5869 (extract+expand); salt=None -> HashLen zero bytes,
    # matching Rust's `Hkdf::<Sha256>::new(None, ikm)`.
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(
        ikm
    )


@dataclass(frozen=True)
class MessageBackupKey:
    """The two keys used by the backup envelope: HMAC-SHA256 key and AES-256 key."""

    hmac_key: bytes  # 32 bytes
    aes_key: bytes  # 32 bytes


def derive_backup_key(aep: str) -> bytes:
    """AEP (recovery key) -> 32-byte BackupKey."""
    aep = normalize_aep(aep)
    if len(aep) != AEP_LEN:
        raise ValueError(
            f"Account Entropy Pool must be {AEP_LEN} characters, got {len(aep)}"
        )
    try:
        ikm = aep.encode("ascii")
    except UnicodeEncodeError as e:
        raise ValueError("Account Entropy Pool must be ASCII") from e
    return _hkdf(ikm, 32, _BACKUP_KEY_INFO)


def derive_local_backup_metadata_key(backup_key: bytes) -> bytes:
    """BackupKey -> 32-byte key that encrypts the local archive's `metadata` file.

    Depends only on the BackupKey (i.e. only the AEP), which is why a local archive
    can be decrypted fully offline.
    """
    return _hkdf(backup_key, 32, _LOCAL_METADATA_KEY_INFO)


def derive_message_backup_key(backup_key: bytes, backup_id: bytes) -> MessageBackupKey:
    """BackupKey + BackupId -> MessageBackupKey."""
    out = _hkdf(backup_key, 64, _MSG_DST + backup_id)
    return MessageBackupKey(hmac_key=out[:32], aes_key=out[32:])
