"""HTML export smoke test over synthetic frames (reuses the export test's fixtures)."""

from signal_backup_decrypt.html import export_html
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
