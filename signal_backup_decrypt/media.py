"""Decrypt attachment media from a local archive's shared `files/` directory.

Each attachment referenced by a message's FilePointer is stored on disk as
    files/<name[:2]>/<name>   where   name = hex(sha256(plaintextHash || localKey))
and encrypted with the standard Signal attachment cipher (LocalArchiver.kt ->
AttachmentCipherOutputStream): 64-byte localKey split into AES(32)+MAC(32), layout
    IV(16) || AES-256-CBC/PKCS5(plaintext) || HMAC-SHA256(32)
with the MAC over IV||ciphertext. The plaintext is zero-padded to a bucket size, so we
truncate to the FilePointer's plaintext `size`.
"""

from __future__ import annotations

import hashlib
import hmac
import mimetypes
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .proto import backup_pb2


class MediaError(Exception):
    pass


def media_name(plaintext_hash: bytes, local_key: bytes) -> str:
    return hashlib.sha256(plaintext_hash + local_key).hexdigest()


def _kind(content_type: str) -> str:
    top = content_type.split("/", 1)[0]
    return top if top in {"image", "video", "audio"} else "file"


def _decrypt(blob: bytes, local_key: bytes, size: int) -> bytes:
    if len(local_key) != 64:
        raise MediaError(f"localKey must be 64 bytes, got {len(local_key)}")
    if len(blob) < 16 + 32:
        raise MediaError("attachment file too short")
    aes_key, mac_key = local_key[:32], local_key[32:]
    body, tag = blob[:-32], blob[-32:]
    if not hmac.compare_digest(hmac.new(mac_key, body, "sha256").digest(), tag):
        raise MediaError("attachment MAC mismatch")
    iv, ciphertext = body[:16], body[16:]
    plain = (
        Cipher(algorithms.AES(aes_key), modes.CBC(iv)).decryptor().update(ciphertext)
    )
    # plain = content(size) + padding-stream zeros + PKCS7; truncating to size recovers the original.
    return plain[:size] if size else plain


class MediaExtractor:
    """Locates, decrypts, and writes out attachment media, caching by on-disk name.

    Files already present in out_dir are reused instead of re-decrypted (the output
    name is derived from the content-addressed media name, so an existing file is
    guaranteed to be the same content) unless `force` is set.
    """

    def __init__(self, files_dir: Path, out_dir: Path, force: bool = False):
        self.files_dir = files_dir
        self.out_dir = out_dir
        self.force = force
        self.on_extract = (
            None  # optional no-arg callback, fired per extract() (progress bars)
        )
        self._cache: dict[str, dict | None] = {}
        self.decrypted = 0
        self.reused = 0
        self.missing = 0
        self.failed = 0

    def extract(self, pointer: backup_pb2.FilePointer) -> dict | None:
        """Return {src, kind, contentType, fileName} for a FilePointer, or None if unavailable."""
        if self.on_extract is not None:
            self.on_extract()
        loc = pointer.locatorInfo
        if not loc.localKey or loc.WhichOneof("integrityCheck") != "plaintextHash":
            return None  # not a locally-stored, downloaded attachment
        name = media_name(loc.plaintextHash, loc.localKey)
        if name in self._cache:
            return self._cache[name]

        result = self._extract(name, loc, pointer)
        self._cache[name] = result
        return result

    def _extract(self, name: str, loc, pointer) -> dict | None:
        content_type = pointer.contentType or "application/octet-stream"
        ext = mimetypes.guess_extension(content_type) or ".bin"
        out_name = name[:16] + ext
        result = {
            "src": f"{self.out_dir.name}/{out_name}",
            "kind": _kind(content_type),
            "contentType": content_type,
            "fileName": pointer.fileName or out_name,
        }
        if not self.force and (self.out_dir / out_name).is_file():
            self.reused += 1
            return result

        disk = self.files_dir / name[:2] / name
        if not disk.is_file():
            self.missing += 1
            return None
        try:
            plaintext = _decrypt(disk.read_bytes(), loc.localKey, loc.size)
        except MediaError:
            self.failed += 1
            return None

        self.out_dir.mkdir(parents=True, exist_ok=True)
        (self.out_dir / out_name).write_bytes(plaintext)
        self.decrypted += 1
        return result
