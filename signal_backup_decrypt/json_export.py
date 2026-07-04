"""Export a Backup to JSON: one manifest + one file per chat.

Message bodies are kept as the raw protobuf (via MessageToDict) so nothing is lost for
archiving; we add a couple of resolved convenience fields (author name, direction).
"""

from __future__ import annotations

import json
from pathlib import Path

from google.protobuf.json_format import MessageToDict

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


def export_json(backup: Backup, out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)

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
        (out_dir / filename).write_text(
            json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8"
        )
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
    manifest_path = out_dir / "manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    return manifest_path
