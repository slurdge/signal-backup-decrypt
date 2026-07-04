"""HTML export smoke test over synthetic frames (reuses the export test's fixtures)."""

import hashlib

from signal_backup_decrypt.html import _AVATAR_COLORS, _avatar_colors, export_html
from signal_backup_decrypt.model import Backup
from signal_backup_decrypt.proto import backup_pb2
from tests.test_export import _frames


def test_html_export(tmp_path):
    info = backup_pb2.BackupInfo(version=1, backupTimeMs=1700000000000)
    backup = Backup.from_frames(info, _frames())
    index = export_html(backup, tmp_path)
    html = index.read_text(encoding="utf-8")
    assert "Alice" in html
    assert "hello there" in html
    assert 'class="chat"' in html  # a conversation pane was rendered
    assert 'style="background:#' in html  # avatars carry Signal's palette colors


def test_avatar_colors_stored():
    r = backup_pb2.Recipient(id=1)
    r.contact.avatarColor = backup_pb2.AvatarColor.Value("A130")
    assert _avatar_colors(r) == _AVATAR_COLORS["A130"]


def test_avatar_colors_hash_fallback():
    # No avatarColor: AvatarColorHash rule, first byte of SHA-256(aci) mod palette size.
    r = backup_pb2.Recipient(id=2)
    r.contact.aci = bytes(range(16))
    idx = hashlib.sha256(bytes(range(16))).digest()[0] % len(_AVATAR_COLORS)
    assert _avatar_colors(r) == list(_AVATAR_COLORS.values())[idx]


def test_avatar_colors_unknown_recipient():
    assert _avatar_colors(None) == _AVATAR_COLORS["A100"]
