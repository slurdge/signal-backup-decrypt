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


def _msg(chat_id, author_id, ts, body, incoming=True):
    f = backup_pb2.Frame()
    f.chatItem.chatId = chat_id
    f.chatItem.authorId = author_id
    f.chatItem.dateSent = ts
    if incoming:
        f.chatItem.incoming.dateReceived = ts
    else:
        f.chatItem.outgoing.SetInParent()
    f.chatItem.standardMessage.text.body = body
    return f


def test_clustering_marks_same_sender_runs(tmp_path):
    t0 = 1700000000000
    frames = _frames() + [
        _msg(10, 2, t0 + 1_000, "second in a row"),  # joins the fixture's first msg
        _msg(10, 2, t0 + 2_000, "third in a row"),
        _msg(10, 1, t0 + 3_000, "reply", incoming=False),  # direction flips: new block
        _msg(
            10, 2, t0 + 10 * 60 * 1000, "much later"
        ),  # same sender, but too far apart
    ]
    backup = Backup.from_frames(backup_pb2.BackupInfo(version=1), frames)
    html = export_html(backup, tmp_path).read_text(encoding="utf-8")

    # " joined-*" with the leading space matches the class attribute, not the CSS rules.
    assert html.count(" joined-prev") == 2  # 2nd and 3rd bubble continue the run
    assert html.count(" joined-next") == 2  # 1st and 2nd bubble are continued
    assert (
        'class="row out joined' not in html
    )  # the reply and the late message stand alone
    # Time only on the last bubble of each run: the 3-run shows one, the two loners one each.
    assert html.count('class="time') == 3


def test_reactions_grouped_with_hover_names(tmp_path):
    frames = _frames()
    reactions = frames[-1].chatItem.standardMessage.reactions
    reactions.add(emoji="❤", authorId=1)  # authorId 1 is the account owner ("You")
    reactions.add(emoji="❤", authorId=2)
    reactions.add(emoji="😀", authorId=2)
    backup = Backup.from_frames(backup_pb2.BackupInfo(version=1), frames)
    html = export_html(backup, tmp_path).read_text(encoding="utf-8")

    assert (
        '<span title="You, Alice">❤ 2</span>' in html
    )  # collapsed, counted, names on hover
    assert '<span title="Alice">😀</span>' in html  # single reaction: no counter
    assert "Note to Self" not in html  # owner reads "You", not the chat title


def test_links_and_youtube(tmp_path):
    frames = _frames() + [
        _msg(
            10,
            2,
            1700000100000,
            "see https://example.com/a. then https://youtu.be/dQw4w9WgXcQ ok",
        ),
    ]
    backup = Backup.from_frames(backup_pb2.BackupInfo(version=1), frames)
    html = export_html(backup, tmp_path).read_text(encoding="utf-8")

    # Bare URLs become links; trailing sentence punctuation stays outside the href.
    assert (
        '<a href="https://example.com/a" target="_blank" rel="noopener">'
        "https://example.com/a</a>."
    ) in html
    assert 'data-id="dQw4w9WgXcQ"' in html  # click-to-load YouTube placeholder
    assert 'id="lightbox"' in html


def test_linkify_escapes_html(tmp_path):
    frames = _frames() + [
        _msg(10, 2, 1700000100000, "<b>bold?</b> https://e.com/?a=1&b=2")
    ]
    backup = Backup.from_frames(backup_pb2.BackupInfo(version=1), frames)
    html = export_html(backup, tmp_path).read_text(encoding="utf-8")
    assert "<b>bold?</b>" not in html  # message text is still escaped
    assert 'href="https://e.com/?a=1&amp;b=2"' in html


def test_date_headers_one_per_day(tmp_path):
    t0 = 1700000000000  # 2023-11-14 UTC (local date may differ; only counts matter)
    frames = _frames() + [
        _msg(10, 2, t0 + 60_000, "same day"),
        _msg(10, 2, t0 + 3 * 24 * 3600 * 1000, "three days later"),
    ]
    backup = Backup.from_frames(backup_pb2.BackupInfo(version=1), frames)
    html = export_html(backup, tmp_path).read_text(encoding="utf-8")
    assert (
        html.count('class="date-header"') == 2
    )  # one per distinct day, not per message
