"""Model indexing + JSON export over synthetic frames (no crypto needed)."""

import json

from signal_backup_decrypt.json_export import export_json
from signal_backup_decrypt.model import Backup
from signal_backup_decrypt.proto import backup_pb2


def _frames():
    f_self = backup_pb2.Frame()
    f_self.recipient.id = 1
    f_self.recipient.self.SetInParent()

    f_alice = backup_pb2.Frame()
    f_alice.recipient.id = 2
    f_alice.recipient.contact.aci = bytes(range(16))
    f_alice.recipient.contact.profileGivenName = "Alice"

    f_chat = backup_pb2.Frame()
    f_chat.chat.id = 10
    f_chat.chat.recipientId = 2

    f_msg = backup_pb2.Frame()
    f_msg.chatItem.chatId = 10
    f_msg.chatItem.authorId = 2
    f_msg.chatItem.dateSent = 1700000000000
    f_msg.chatItem.incoming.dateReceived = 1700000000500
    f_msg.chatItem.standardMessage.text.body = "hello there"
    return [f_self, f_alice, f_chat, f_msg]


def test_json_export(tmp_path):
    info = backup_pb2.BackupInfo(version=1, backupTimeMs=1700000000000)
    backup = Backup.from_frames(info, _frames())

    assert backup.self_id == 1
    assert backup.display_name(2) == "Alice"

    manifest_path = export_json(backup, tmp_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["counts"] == {"recipients": 2, "chats": 1, "messages": 1}

    chat = json.loads((tmp_path / "chat-10.json").read_text(encoding="utf-8"))
    assert chat["name"] == "Alice"
    msg = chat["messages"][0]
    assert msg["authorName"] == "Alice"
    assert msg["direction"] == "incoming"
    assert msg["standardMessage"]["text"]["body"] == "hello there"
