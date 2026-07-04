"""Render a Backup to a single self-contained, browsable HTML file (Signal-like two pane).

Text messages, attachments, and the common system/update messages render properly;
richer item types (payments, gift badges, polls, view-once) degrade to labeled
placeholders. Contact photos are not in a backup (Signal refetches them from the
profile CDN after restore), so avatars are the app's colored-initial style.
"""

from __future__ import annotations

import hashlib
from datetime import datetime
from pathlib import Path

from jinja2 import Environment, PackageLoader, select_autoescape

from .model import Backup
from .proto import backup_pb2

_VOICE = backup_pb2.MessageAttachment.VOICE_MESSAGE

# Signal's avatar palette (Signal-Android AvatarColor.java backgrounds + Avatars.kt
# ForegroundColor). Insertion order matches the backup.proto AvatarColor enum
# (A100=0 .. A210=11), which is also AvatarColorHash's fallback order.
_AVATAR_COLORS = {
    "A100": ("#E3E3FE", "#3838F5"),
    "A110": ("#DDE7FC", "#1251D3"),
    "A120": ("#D8E8F0", "#086DA0"),
    "A130": ("#CDE4CD", "#067906"),
    "A140": ("#EAE0F8", "#661AFF"),
    "A150": ("#F5E3FE", "#9F00F0"),
    "A160": ("#F6D8EC", "#B8057C"),
    "A170": ("#F5D7D7", "#BE0404"),
    "A180": ("#FEF5D0", "#836B01"),
    "A190": ("#EAE6D5", "#7D6F40"),
    "A200": ("#D2D2DC", "#4F4F6D"),
    "A210": ("#D7D7D9", "#5C5C5C"),
}
_AVATAR_FALLBACK_ORDER = list(_AVATAR_COLORS)


def _avatar_colors(r: backup_pb2.Recipient | None) -> tuple[str, str]:
    """(background, foreground) for a recipient's initial-avatar, like the app shows.

    Uses the stored avatarColor when set; otherwise Signal's documented fallback
    (AvatarColorHash.kt): first byte of SHA-256(contact id) modulo the palette size.
    """
    code = None
    data = None
    kind = r.WhichOneof("destination") if r is not None else None
    if kind == "contact":
        c = r.contact
        if c.HasField("avatarColor"):
            code = backup_pb2.AvatarColor.Name(c.avatarColor)
        elif c.aci:
            data = c.aci
        elif c.e164:
            data = f"+{c.e164}".encode()
        elif c.pni:
            data = b"\x01" + c.pni  # ServiceIdToBinary prefixes a PNI with 0x01
    elif kind == "group":
        g = r.group
        if g.HasField("avatarColor"):
            code = backup_pb2.AvatarColor.Name(g.avatarColor)
        else:
            data = g.masterKey  # approximation: the app hashes the zkgroup-derived group id
    elif kind == "self" and getattr(r, "self").HasField("avatarColor"):
        code = backup_pb2.AvatarColor.Name(getattr(r, "self").avatarColor)
    if code is None and data:
        code = _AVATAR_FALLBACK_ORDER[hashlib.sha256(data).digest()[0] % len(_AVATAR_FALLBACK_ORDER)]
    return _AVATAR_COLORS.get(code, _AVATAR_COLORS["A100"])


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
    author_bg, author_fg = _avatar_colors(backup.recipients.get(item.authorId))
    v = {
        "css": {"incoming": "in", "outgoing": "out"}.get(direction, "system"),
        "author": backup.display_name(item.authorId),
        "author_fg": author_fg,  # author-name color on light theme
        "author_bg": author_bg,  # the pastel variant reads better on dark bubbles
        "show_author": False,    # set per-chat: group chats, first bubble of a run
        "ts": item.dateSent,
        "joined_prev": False,
        "joined_next": False,
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


_CLUSTER_MS = 3 * 60 * 1000  # like the app: same sender within a few minutes reads as one block


def _mark_clusters(views: list[dict]) -> None:
    """Flag bubbles that continue a same-sender run, so CSS can square the inner corners."""
    def joined(a: dict | None, b: dict | None) -> bool:
        return (
            a is not None and b is not None
            and a["css"] == b["css"] and a["css"] in ("in", "out")
            and a["author"] == b["author"]
            and b["ts"] - a["ts"] <= _CLUSTER_MS
        )

    for prev, cur in zip(views, views[1:]):
        if joined(prev, cur):
            prev["joined_next"] = True
            cur["joined_prev"] = True


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
        recipient = backup.recipients.get(chat.recipientId)
        avatar_bg, avatar_fg = _avatar_colors(recipient)
        is_group = recipient is not None and recipient.WhichOneof("destination") == "group"
        views = [_view(backup, it, media) for it in items]
        _mark_clusters(views)
        for m in views:  # author names: only in group chats, only atop a run (like the app)
            m["show_author"] = is_group and m["css"] == "in" and not m["joined_prev"]
        chats.append(
            {
                "id": chat.id,
                "name": name,
                "initial": (name.strip()[:1] or "?").upper(),
                "avatar_bg": avatar_bg,
                "avatar_fg": avatar_fg,
                "count": len(items),
                "messages": views,
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
