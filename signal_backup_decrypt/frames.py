"""Parse the decrypted plaintext: a stream of varint-length-delimited protobufs.

Layout (message-backup/src/frame.rs, parse.rs):
    <varint len><BackupInfo>  <varint len><Frame>  <varint len><Frame> ...
The first message is always BackupInfo; every message after it is a Frame.
"""

from __future__ import annotations

from collections.abc import Iterator

from .proto import backup_pb2


def read_varint(buf, pos: int) -> tuple[int, int]:
    """Decode a base-128 varint at buf[pos]; return (value, new_pos)."""
    result = 0
    shift = 0
    while True:
        if pos >= len(buf):
            raise ValueError("truncated varint")
        byte = buf[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, pos
        shift += 7
        if shift >= 64:
            raise ValueError("varint too long")


def read_frames(
    plaintext: bytes,
) -> tuple[backup_pb2.BackupInfo, Iterator[backup_pb2.Frame]]:
    """Return (BackupInfo, iterator of Frames) over the decrypted plaintext."""
    view = memoryview(plaintext)
    length, pos = read_varint(view, 0)
    info = backup_pb2.BackupInfo.FromString(bytes(view[pos : pos + length]))
    pos += length

    def frames(pos: int) -> Iterator[backup_pb2.Frame]:
        while pos < len(view):
            length, pos = read_varint(view, pos)
            yield backup_pb2.Frame.FromString(bytes(view[pos : pos + length]))
            pos += length

    return info, frames(pos)
