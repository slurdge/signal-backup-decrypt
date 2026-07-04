"""Export a Backup to a zip archive: manifest.json + one chat-N.json per chat + media.

Everything is built in memory and returned as bytes so the caller decides where (and
whether) to write to disk.
"""

from __future__ import annotations

import io
import json
import mimetypes
import zipfile
from collections.abc import Callable
from pathlib import Path

from google.protobuf.json_format import MessageToDict

from .media import MediaError, _decrypt, media_name
from .model import Backup
from .proto import backup_pb2


def _to_dict(msg) -> dict:
    return MessageToDict(msg, preserving_proto_field_name=True)


def _direction(item: backup_pb2.ChatItem) -> str:
    return {
        "incoming": "incoming",
        "outgoing": "outgoing",
        "directionless": "update",
    }.get(item.WhichOneof("directionalDetails") or "", "unknown")


def _add_pointer(
    zf: zipfile.ZipFile,
    files_dir: Path,
    pointer: backup_pb2.FilePointer,
    seen: set[str],
    on_media: Callable[[], None] | None,
) -> None:
    """Decrypt one FilePointer into the zip under media/; skip if already added."""
    if on_media is not None:
        on_media()
    loc = pointer.locatorInfo
    if not loc.localKey or loc.WhichOneof("integrityCheck") != "plaintextHash":
        return
    name = media_name(loc.plaintextHash, loc.localKey)
    content_type = pointer.contentType or "application/octet-stream"
    ext = mimetypes.guess_extension(content_type) or ".bin"
    out_name = name[:16] + ext
    zip_path = f"media/{out_name}"
    if zip_path in seen:
        return
    seen.add(zip_path)
    disk = files_dir / name[:2] / name
    if not disk.is_file():
        return
    try:
        plaintext = _decrypt(disk.read_bytes(), loc.localKey, loc.size)
        zf.writestr(zip_path, plaintext)
    except MediaError:
        pass


def export_json(
    backup: Backup,
    files_dir: Path | None = None,
    *,
    on_media: Callable[[], None] | None = None,
) -> bytes:
    """Build and return a zip archive containing all chats as JSON plus media files."""
    buf = io.BytesIO()
    seen_media: set[str] = set()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        chats_meta = []
        for chat in backup.chats_sorted():
            items = backup.messages.get(chat.id, [])
            name = backup.display_name(chat.recipientId)
            filename = f"chat-{chat.id}.json"
            payload = {
                "id": chat.id,
                "name": name,
                "recipientId": chat.recipientId,
                "messageCount": len(items),
                "messages": [
                    {
                        "authorName": backup.display_name(item.authorId),
                        "direction": _direction(item),
                        **_to_dict(item),
                    }
                    for item in items
                ],
            }
            zf.writestr(filename, json.dumps(payload, indent=2, ensure_ascii=False))
            chats_meta.append(
                {
                    "id": chat.id,
                    "name": name,
                    "recipientId": chat.recipientId,
                    "messageCount": len(items),
                    "file": filename,
                }
            )

        manifest = {
            "version": backup.info.version,
            "backupTimeMs": backup.info.backupTimeMs,
            "counts": {
                "recipients": len(backup.recipients),
                "chats": len(backup.chats),
                "messages": sum(len(v) for v in backup.messages.values()),
            },
            "recipients": [
                {
                    "id": rid,
                    "type": r.WhichOneof("destination"),
                    "name": backup.display_name(rid),
                }
                for rid, r in sorted(backup.recipients.items())
            ],
            "chats": chats_meta,
        }
        zf.writestr("manifest.json", json.dumps(manifest, indent=2, ensure_ascii=False))

        if files_dir is not None:
            for items in backup.messages.values():
                for item in items:
                    kind = item.WhichOneof("item")
                    if kind == "standardMessage":
                        sm = item.standardMessage
                        for att in sm.attachments:
                            _add_pointer(
                                zf, files_dir, att.pointer, seen_media, on_media
                            )
                        for lp in sm.linkPreview:
                            if lp.HasField("image"):
                                _add_pointer(
                                    zf, files_dir, lp.image, seen_media, on_media
                                )
                    elif kind == "stickerMessage":
                        st = item.stickerMessage.sticker
                        _add_pointer(zf, files_dir, st.data, seen_media, on_media)

    return buf.getvalue()
