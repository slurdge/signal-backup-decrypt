"""Render a Backup to a single self-contained, browsable HTML file (Signal-like two pane).

Text messages and the common system/update messages render properly; richer item types
(payments, gift badges, polls, view-once, stickers-as-images) degrade to labeled
placeholders. Media bytes aren't in a v2 message backup, so attachments show as chips.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from jinja2 import Environment, PackageLoader, select_autoescape

from .model import Backup
from .proto import backup_pb2

_VOICE = backup_pb2.MessageAttachment.VOICE_MESSAGE


def _fmt_time(ms: int) -> str:
    if not ms:
        return ""
    return datetime.fromtimestamp(ms / 1000).strftime("%Y-%m-%d %H:%M")


def _attachment_label(att: backup_pb2.MessageAttachment) -> str:
    p = att.pointer
    ct = p.contentType or ""
    if att.flag == _VOICE:
        icon = "🎤"
    elif ct.startswith("image"):
        icon = "🖼"
    elif ct.startswith("video"):
        icon = "🎞"
    elif ct.startswith("audio"):
        icon = "🎵"
    else:
        icon = "📎"
    return f"{icon} {p.fileName or ct or 'attachment'}"


def _reaction(backup: Backup, r: backup_pb2.Reaction) -> str:
    return f"{r.emoji} {backup.display_name(r.authorId)}"


def _update_label(item: backup_pb2.ChatItem) -> str:
    if item.WhichOneof("item") != "updateMessage":
        return "Message"
    um = item.updateMessage
    kind = um.WhichOneof("update")
    if kind == "simpleUpdate":
        name = backup_pb2.SimpleChatUpdate.Type.Name(um.simpleUpdate.type)
        return name.replace("_", " ").capitalize()
    if not kind:
        return "Update"
    # Humanize the oneof field name, e.g. "expirationTimerChange" -> "Expiration timer change".
    words = "".join(f" {c.lower()}" if c.isupper() else c for c in kind).strip()
    return words.capitalize()


def _attach(v: dict, media, pointer, fallback: str) -> None:
    """Resolve one attachment to inline media, or fall back to a labeled note."""
    resolved = media.extract(pointer) if media is not None else None
    if resolved:
        v["media"].append(resolved)
    elif fallback:
        v["notes"].append(fallback)


def _view(backup: Backup, item: backup_pb2.ChatItem, media=None) -> dict:
    direction = item.WhichOneof("directionalDetails")
    kind = item.WhichOneof("item")
    v = {
        "css": {"incoming": "in", "outgoing": "out"}.get(direction, "system"),
        "author": backup.display_name(item.authorId),
        "time": _fmt_time(item.dateSent),
        "body": "",
        "notes": [],
        "media": [],
        "reactions": [],
        "quote": None,
        "system": None,
    }

    if kind == "standardMessage":
        sm = item.standardMessage
        if sm.HasField("text"):
            v["body"] = sm.text.body
        for a in sm.attachments:
            _attach(v, media, a.pointer, _attachment_label(a))
        for lp in sm.linkPreview:
            v["notes"].append(f"🔗 {lp.url}")
            if lp.HasField("image"):
                _attach(v, media, lp.image, "")
        if sm.HasField("quote"):
            q = sm.quote
            v["quote"] = {
                "author": backup.display_name(q.authorId),
                "text": q.text.body if q.HasField("text") else "",
            }
        v["reactions"] = [_reaction(backup, r) for r in sm.reactions]
    elif kind == "stickerMessage":
        st = item.stickerMessage.sticker
        _attach(v, media, st.data, f"[Sticker {st.emoji}]".replace(" ]", "]"))
        v["reactions"] = [_reaction(backup, r) for r in item.stickerMessage.reactions]
    elif kind == "remoteDeletedMessage" or kind == "adminDeletedMessage":
        v["notes"] = ["🗑 This message was deleted"]
    elif kind == "contactMessage":
        v["notes"] = ["[Shared contact]"]
        v["reactions"] = [_reaction(backup, r) for r in item.contactMessage.reactions]
    elif kind == "viewOnceMessage":
        v["notes"] = ["[View-once media]"]
    elif kind == "paymentNotification":
        v["notes"] = ["[Payment]"]
    elif kind == "giftBadge":
        v["notes"] = ["[Gift badge]"]
    elif kind == "poll":
        v["notes"] = ["[Poll]"]
    elif kind == "updateMessage" or v["css"] == "system":
        v["css"] = "system"
        v["system"] = _update_label(item)
    elif kind:
        v["notes"] = [f"[{kind}]"]
    return v


def export_html(backup: Backup, out_dir: Path, media=None) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    env = Environment(
        loader=PackageLoader("signal_backup_decrypt", "templates"),
        autoescape=select_autoescape(),
    )

    chats = []
    for chat in backup.chats_sorted():
        items = backup.messages.get(chat.id, [])
        name = backup.display_name(chat.recipientId)
        chats.append(
            {
                "id": chat.id,
                "name": name,
                "initial": (name.strip()[:1] or "?").upper(),
                "count": len(items),
                "messages": [_view(backup, it, media) for it in items],
            }
        )

    html = env.get_template("index.html").render(
        chats=chats,
        generated=datetime.now().strftime("%Y-%m-%d %H:%M"),
        backup_time=_fmt_time(backup.info.backupTimeMs),
    )
    index = out_dir / "index.html"
    index.write_text(html, encoding="utf-8")
    return index
