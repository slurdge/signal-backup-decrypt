"""Command-line entry point: decrypt / json / html a new-format Signal backup."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Annotated, Optional

import typer
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

app = typer.Typer(
    name="signal-backup",
    help="Decrypt a new-format (v2) Signal Android backup.",
    no_args_is_help=True,
)

_SOURCE = Annotated[Path, typer.Argument(help="local archive folder (the snapshot dir or its parent)")]
_OUTPUT = Annotated[Optional[Path], typer.Option("-o", "--output")]


def _fail(msg: str):
    _err.print(f"[bold red]error:[/] {msg}")
    raise SystemExit(1)


def _get_aep() -> str:
    aep = os.environ.get("SIGNAL_AEP")
    if not aep:
        aep = Prompt.ask(
            "Account Entropy Pool (recovery key)", password=True, console=console
        )
    aep = normalize_aep(aep)
    if len(aep) != AEP_LEN:
        _fail(f"AEP must be {AEP_LEN} characters after removing spaces, got {len(aep)}")
    return aep


def _find_snapshot(source: Path) -> Path:
    from .local import find_snapshot

    if not source.exists():
        _fail(f"no such directory: {source}")
    if not source.is_dir():
        _fail(f"{source} is not a local archive folder (the snapshot dir or its parent)")
    return find_snapshot(source)


def _decrypt_to_frames(source: Path):
    from .local import message_key_for_snapshot

    snapshot = _find_snapshot(source)
    aep = _get_aep()
    key = message_key_for_snapshot(snapshot, aep)
    data = (snapshot / "main").read_bytes()
    if has_forward_secrecy(data):
        _fail("this snapshot's main archive uses forward secrecy (unsupported)")
    candidate = snapshot.parent / "files"
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


@app.command()
def decrypt(
    source: _SOURCE,
    output: _OUTPUT = None,
) -> None:
    """Decrypt to the raw plaintext frame stream (debug)."""
    _, plaintext, _ = _decrypt_to_frames(source)
    out = output or Path("frames.bin")
    out.write_bytes(plaintext)
    console.print(
        f"[green]✓[/] Wrote {len(plaintext)} bytes of decrypted frame stream to [bold]{out}[/]"
    )


@app.command()
def json(
    source: _SOURCE,
    output: _OUTPUT = None,
    no_media: Annotated[bool, typer.Option("--no-media", help="skip decrypting attachments")] = False,
) -> None:
    """Export chats + media as a self-contained zip (backup.zip)."""
    from .json import export_json

    backup, _, files_dir = _decrypt_to_frames(source)
    out_path = output or Path("backup.zip")

    if files_dir and not no_media:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("Building zip", total=_count_media_refs(backup))
            data = export_json(backup, files_dir, on_media=lambda: progress.advance(task))
    else:
        with console.status("Building zip…"):
            data = export_json(backup)

    out_path.write_bytes(data)
    console.print(f"[green]✓[/] Wrote {len(data) / 1e6:.1f} MB zip to [bold]{out_path}[/]")


@app.command()
def html(
    source: _SOURCE,
    output: _OUTPUT = None,
    no_media: Annotated[bool, typer.Option("--no-media", help="skip decrypting attachments")] = False,
    force_files: Annotated[bool, typer.Option("--force-files", help="re-decrypt media even if already extracted")] = False,
) -> None:
    """Render a browsable HTML archive."""
    from .html import export_html
    from .media import MediaExtractor

    backup, _, files_dir = _decrypt_to_frames(source)
    out_dir = output or Path("out")

    media = None
    if files_dir and not no_media:
        media = MediaExtractor(files_dir, out_dir / "media", force=force_files)
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


@app.command("change-key")
def change_key(
    source: _SOURCE,
    output: _OUTPUT = None,
) -> None:
    """Re-encrypt under a fresh random AEP (for testing)."""
    from .keys import display_aep, generate_aep
    from .local import rekey_snapshot

    snapshot = _find_snapshot(source)
    out_dir = output or snapshot.parent / f"{snapshot.name}-rekeyed"
    if out_dir.resolve() == snapshot.resolve():
        _fail("refusing to rekey the snapshot in place; pick a different -o directory")

    new_aep = generate_aep()
    with console.status("Re-encrypting under the new key…"):
        rekey_snapshot(snapshot, _get_aep(), new_aep, out_dir)
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


@app.command()
def verify(
    source: _SOURCE,
) -> None:
    """Diagnose whether the AEP is correct for the archive."""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    from .keys import derive_backup_key, derive_message_backup_key
    from .local import recover_backup_id

    snapshot = _find_snapshot(source)
    aep = _get_aep()
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
    try:
        app(args=argv)
    except BackupDecryptError as e:
        _fail(str(e))


if __name__ == "__main__":
    main()
