"""A thin in-memory index over decoded frames: recipients, chats, and messages.

Deliberately minimal — just enough to resolve who-said-what-in-which-chat for the
JSON and HTML exporters. Raw protobuf objects are kept; we don't copy them into new
shapes (the exporters read fields directly).
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from dataclasses import dataclass

from .proto import backup_pb2


@dataclass
class Backup:
    info: backup_pb2.BackupInfo
    recipients: dict[int, backup_pb2.Recipient]
    chats: dict[int, backup_pb2.Chat]
    messages: dict[int, list[backup_pb2.ChatItem]]  # chatId -> items sorted by dateSent
    self_id: int | None

    @classmethod
    def from_frames(cls, info: backup_pb2.BackupInfo, frames: Iterable[backup_pb2.Frame]) -> "Backup":
        recipients: dict[int, backup_pb2.Recipient] = {}
        chats: dict[int, backup_pb2.Chat] = {}
        messages: dict[int, list[backup_pb2.ChatItem]] = {}
        self_id: int | None = None
        for frame in frames:
            kind = frame.WhichOneof("item")
            if kind == "recipient":
                r = frame.recipient
                recipients[r.id] = r
                if r.WhichOneof("destination") == "self":
                    self_id = r.id
            elif kind == "chat":
                chats[frame.chat.id] = frame.chat
            elif kind == "chatItem":
                messages.setdefault(frame.chatItem.chatId, []).append(frame.chatItem)
            # account / stickerPack / adHocCall / notificationProfile / chatFolder: not indexed yet
        for items in messages.values():
            items.sort(key=lambda ci: ci.dateSent)
        return cls(info, recipients, chats, messages, self_id)

    def chats_sorted(self) -> Iterator[backup_pb2.Chat]:
        """Chats ordered by most recent message first (empty chats last)."""
        def last_ts(chat: backup_pb2.Chat) -> int:
            items = self.messages.get(chat.id)
            return items[-1].dateSent if items else 0
        return iter(sorted(self.chats.values(), key=last_ts, reverse=True))

    def display_name(self, recipient_id: int) -> str:
        r = self.recipients.get(recipient_id)
        if r is None:
            return f"Unknown (#{recipient_id})"
        return _recipient_name(r)


def _recipient_name(r: backup_pb2.Recipient) -> str:
    kind = r.WhichOneof("destination")
    if kind == "contact":
        return _contact_name(r.contact)
    if kind == "group":
        return _group_title(r.group) or f"Group (#{r.id})"
    if kind == "self":
        return "Note to Self"
    if kind == "releaseNotes":
        return "Signal"
    if kind == "callLink":
        return r.callLink.name or "Call link"
    if kind == "distributionList":
        dl = r.distributionList
        if dl.WhichOneof("item") == "distributionList":
            return dl.distributionList.name or "My Story"
        return "Story"
    return f"Recipient #{r.id}"


def _contact_name(c: backup_pb2.Contact) -> str:
    nick = " ".join(p for p in (c.nickname.given, c.nickname.family) if p).strip()
    profile = " ".join(p for p in (c.profileGivenName, c.profileFamilyName) if p).strip()
    system = " ".join(p for p in (c.systemGivenName, c.systemFamilyName) if p).strip()
    if nick:
        return nick
    if profile:
        return profile
    if system:
        return system
    if c.username:
        return c.username
    if c.e164:
        return f"+{c.e164}"
    if c.aci:
        return "Unknown contact"
    return "Unknown contact"


def _group_title(g: backup_pb2.Group) -> str:
    title = g.snapshot.title
    # GroupAttributeBlob: title lives in the oneof `content.title`.
    if title.WhichOneof("content") == "title":
        return title.title
    return ""
