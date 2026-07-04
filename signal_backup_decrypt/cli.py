"""Command-line entry point: decrypt / json / html a new-format Signal backup."""

from __future__ import annotations

import argparse
import os
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.prompt import Prompt

from .envelope import BackupDecryptError, decrypt_backup, has_forward_secrecy
from .frames import read_frames
from .keys import AEP_LEN, normalize_aep
from .model import Backup

console = Console()
_err = Console(stderr=True)


def _fail(msg: str):
    _err.print(f"[bold red]error:[/] {msg}")
    raise SystemExit(1)


def _get_aep(args) -> str:
    aep = args.aep or os.environ.get("SIGNAL_AEP")
    if not aep:
        aep = Prompt.ask(
            "Account Entropy Pool (recovery key)", password=True, console=console
        )
    aep = normalize_aep(aep)  # tolerate the grouped, uppercased, display-swapped form
    if len(aep) != AEP_LEN:
        _fail(f"AEP must be {AEP_LEN} characters after removing spaces, got {len(aep)}")
    return aep


def _find_snapshot(args) -> Path:
    from .local import find_snapshot

    path = Path(args.source)
    if not path.exists():
        _fail(f"no such directory: {path}")
    if not path.is_dir():
        _fail(f"{path} is not a local archive folder (the snapshot dir or its parent)")
    return find_snapshot(path)


def _decrypt_to_frames(args):
    """Shared: validate inputs, derive keys, decrypt, return (Backup, plaintext, files_dir).

    The source is a local archive: a snapshot folder (or its parent), with the BackupId
    recovered from the encrypted `metadata` file.
    """
    from .local import message_key_for_snapshot

    snapshot = _find_snapshot(args)
    aep = _get_aep(args)
    key = message_key_for_snapshot(snapshot, aep)
    data = (snapshot / "main").read_bytes()
    if has_forward_secrecy(data):
        _fail("this snapshot's main archive uses forward secrecy (unsupported)")
    candidate = snapshot.parent / "files"  # shared media directory alongside snapshots
    files_dir = candidate if candidate.is_dir() else None

    with console.status("Decrypting and decompressing…"):
        plaintext = decrypt_backup(data, key)
        info, frames = read_frames(plaintext)
        backup = Backup.from_frames(info, frames)
    n_msgs = sum(len(v) for v in backup.messages.values())
    console.print(
        f"[green]✓[/] Decrypted [bold]{snapshot.name}[/]: "
        f"{len(data) / 1e6:.1f} MB → {len(plaintext) / 1e6:.1f} MB, "
        f"{n_msgs} messages in {len(backup.chats)} chats, {len(backup.recipients)} recipients"
    )
    return backup, plaintext, files_dir


def _count_media_refs(backup: Backup) -> int:
    """How many FilePointers the HTML export will try to resolve (progress bar total)."""
    n = 0
    for items in backup.messages.values():
        for it in items:
            kind = it.WhichOneof("item")
            if kind == "standardMessage":
                sm = it.standardMessage
                n += len(sm.attachments)
                n += sum(1 for lp in sm.linkPreview if lp.HasField("image"))
            elif kind == "stickerMessage":
                n += 1
    return n


def _cmd_decrypt(args):
    _, plaintext, _ = _decrypt_to_frames(args)
    out = Path(args.output or "frames.bin")
    out.write_bytes(plaintext)
    console.print(
        f"[green]✓[/] Wrote {len(plaintext)} bytes of decrypted frame stream to [bold]{out}[/]"
    )


def _cmd_json(args):
    from .json_export import export_json

    backup, _, _ = _decrypt_to_frames(args)
    with console.status("Writing JSON…"):
        manifest = export_json(backup, Path(args.output or "out"))
    console.print(
        f"[green]✓[/] Wrote {len(backup.chats)} chats to [bold]{manifest.parent}[/] "
        f"(see {manifest.name})"
    )


def _cmd_html(args):
    from .html import export_html
    from .media import MediaExtractor

    backup, _, files_dir = _decrypt_to_frames(args)
    out_dir = Path(args.output or "out")

    media = None
    if files_dir and not args.no_media:
        media = MediaExtractor(files_dir, out_dir / "media", force=args.force_files)
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("Media", total=_count_media_refs(backup))
            media.on_extract = lambda: progress.advance(task)
            index = export_html(backup, out_dir, media)
        parts = [
            f"[green]{media.decrypted} decrypted[/]",
            f"[cyan]{media.reused} reused[/]",
        ]
        if media.missing:
            parts.append(f"[yellow]{media.missing} missing[/]")
        if media.failed:
            parts.append(f"[red]{media.failed} failed[/]")
        console.print(f"[green]✓[/] Media: {', '.join(parts)}")
    else:
        with console.status("Writing HTML…"):
            index = export_html(backup, out_dir, media)
    console.print(f"[green]✓[/] Wrote HTML to [bold]{index}[/] — open it in a browser")


def _cmd_change_key(args):
    """Re-encrypt the archive under a fresh random key, so tests never touch the real AEP."""
    from .keys import display_aep, generate_aep
    from .local import rekey_snapshot

    snapshot = _find_snapshot(args)
    out_dir = (
        Path(args.output)
        if args.output
        else snapshot.parent / f"{snapshot.name}-rekeyed"
    )
    if out_dir.resolve() == snapshot.resolve():
        _fail("refusing to rekey the snapshot in place; pick a different -o directory")

    new_aep = generate_aep()
    with console.status("Re-encrypting under the new key…"):
        rekey_snapshot(snapshot, _get_aep(args), new_aep, out_dir)
    console.print(f"[green]✓[/] Wrote rekeyed snapshot to [bold]{out_dir}[/]")
    console.print(
        "  Keep it next to the original so the shared files/ media directory is found."
    )
    console.print(
        Panel.fit(
            f"[bold]Canonical:[/]     {new_aep}\n[bold]Signal style:[/]  {display_aep(new_aep)}",
            title="New key",
            border_style="green",
        )
    )


def _cmd_verify(args):
    """Diagnose a local archive without fully decrypting: is the AEP correct?"""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    from .keys import derive_backup_key, derive_message_backup_key
    from .local import recover_backup_id

    snapshot = _find_snapshot(args)
    aep = _get_aep(args)  # normalized: whitespace stripped, #/= un-swapped, lowercased
    charset = set("abcdefghijklmnopqrstuvwxyz0123456789")
    offenders = sorted(set(aep) - charset)
    if len(aep) != AEP_LEN or offenders:
        _fail(
            f"still not a canonical AEP after normalization "
            f"(length {len(aep)}, need {AEP_LEN}; non-alphanumeric: {offenders})"
        )
    console.print(f"[green]✓[/] Key normalizes to {AEP_LEN} chars of [bold]0-9a-z[/]")
    backup_key = derive_backup_key(aep)

    backup_id = recover_backup_id((snapshot / "metadata").read_bytes(), backup_key)
    console.print(
        f"[green]✓[/] BackupId recovered from metadata: [bold]{backup_id.hex()}[/]"
    )

    data = (snapshot / "main").read_bytes()
    if has_forward_secrecy(data):
        console.print(
            "[red]✗[/] main has the forward-secrecy magic (unexpected for a local archive)"
        )
        return
    key = derive_message_backup_key(backup_key, backup_id)
    iv, first_block = data[:16], data[16:32]
    plain0 = (
        Cipher(algorithms.AES(key.aes_key), modes.CBC(iv))
        .decryptor()
        .update(first_block)
    )
    if plain0[:3] == b"\x1f\x8b\x08":
        console.print(
            "[green]✓[/] main decrypts to a gzip header — [bold green]the key works[/]"
        )
    else:
        console.print(
            "[red]✗[/] main does not decrypt to gzip — "
            "[bold red]the AEP is wrong for this backup[/]"
        )


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="signal-backup",
        description="Decrypt a new-format (v2) Signal Android backup.",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)
    for name, handler, help_ in (
        ("decrypt", _cmd_decrypt, "decrypt to the raw plaintext frame stream (debug)"),
        ("json", _cmd_json, "export chats as JSON (manifest + one file per chat)"),
        ("html", _cmd_html, "render a browsable HTML archive"),
        ("verify", _cmd_verify, "diagnose whether the AEP is correct for the archive"),
        (
            "change-key",
            _cmd_change_key,
            "re-encrypt under a fresh random AEP (for testing)",
        ),
    ):
        p = sub.add_parser(name, help=help_)
        p.add_argument(
            "source", help="local archive folder (the snapshot dir or its parent)"
        )
        p.add_argument(
            "--aep", help="Account Entropy Pool (else $SIGNAL_AEP or prompt)"
        )
        p.add_argument(
            "--no-media", action="store_true", help="skip decrypting attachments (html)"
        )
        p.add_argument(
            "--force-files",
            action="store_true",
            help="re-decrypt media even if the output file already exists (html)",
        )
        p.add_argument(
            "-o",
            "--output",
            help="output file (decrypt) or directory (json/html/change-key)",
        )
        p.set_defaults(func=handler)

    args = parser.parse_args(argv)
    try:
        args.func(args)
    except BackupDecryptError as e:
        _fail(str(e))


if __name__ == "__main__":
    main()
