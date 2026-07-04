"""Command-line entry point: decrypt / json / html a new-format Signal backup."""

from __future__ import annotations

import argparse
import getpass
import os
import sys
from pathlib import Path

from .envelope import decrypt_backup, has_forward_secrecy
from .frames import read_frames
from .keys import AEP_LEN, normalize_aep
from .model import Backup


def _get_aep(args) -> str:
    aep = args.aep or os.environ.get("SIGNAL_AEP")
    if not aep:
        aep = getpass.getpass("Account Entropy Pool (recovery key): ")
    aep = normalize_aep(aep)  # tolerate the grouped, uppercased, display-swapped form
    if len(aep) != AEP_LEN:
        sys.exit(f"error: AEP must be {AEP_LEN} characters after removing spaces, got {len(aep)}")
    return aep


def _decrypt_to_frames(args):
    """Shared: validate inputs, derive keys, decrypt, return (Backup, plaintext, files_dir).

    The source is a local archive: a snapshot folder (or its parent), with the BackupId
    recovered from the encrypted `metadata` file.
    """
    path = Path(args.source)
    if not path.exists():
        sys.exit(f"error: no such directory: {path}")
    if not path.is_dir():
        sys.exit(f"error: {path} is not a local archive folder (the snapshot dir or its parent)")
    aep = _get_aep(args)

    from .local import find_snapshot, message_key_for_snapshot

    snapshot = find_snapshot(path)
    key = message_key_for_snapshot(snapshot, aep)
    data = (snapshot / "main").read_bytes()
    if has_forward_secrecy(data):
        sys.exit("error: this snapshot's main archive uses forward secrecy (unsupported)")
    candidate = snapshot.parent / "files"  # shared media directory alongside snapshots
    files_dir = candidate if candidate.is_dir() else None

    plaintext = decrypt_backup(data, key)
    info, frames = read_frames(plaintext)
    return Backup.from_frames(info, frames), plaintext, files_dir


def _cmd_decrypt(args):
    _, plaintext, _ = _decrypt_to_frames(args)
    out = Path(args.output or "frames.bin")
    out.write_bytes(plaintext)
    print(f"Wrote {len(plaintext)} bytes of decrypted frame stream to {out}")


def _cmd_json(args):
    from .json_export import export_json

    backup, _, _ = _decrypt_to_frames(args)
    manifest = export_json(backup, Path(args.output or "out"))
    print(f"Wrote {len(backup.chats)} chats to {manifest.parent}/ (see {manifest.name})")


def _cmd_html(args):
    from .html import export_html
    from .media import MediaExtractor

    backup, _, files_dir = _decrypt_to_frames(args)
    out_dir = Path(args.output or "out")
    media = None
    if files_dir and not args.no_media:
        media = MediaExtractor(files_dir, out_dir / "media")
    index = export_html(backup, out_dir, media)
    if media:
        print(f"Media: {media.decrypted} decrypted, {media.missing} missing, {media.failed} failed")
    print(f"Wrote HTML to {index}")


def _cmd_change_key(args):
    """Re-encrypt the archive under a fresh random key, so tests never touch the real AEP."""
    from .keys import display_aep, generate_aep
    from .local import find_snapshot, rekey_snapshot

    path = Path(args.source)
    if not path.is_dir():
        sys.exit(f"error: {path} is not a local archive folder (the snapshot dir or its parent)")
    snapshot = find_snapshot(path)
    out_dir = Path(args.output) if args.output else snapshot.parent / f"{snapshot.name}-rekeyed"
    if out_dir.resolve() == snapshot.resolve():
        sys.exit("error: refusing to rekey the snapshot in place; pick a different -o directory")

    new_aep = generate_aep()
    rekey_snapshot(snapshot, _get_aep(args), new_aep, out_dir)
    print(f"Wrote rekeyed snapshot to {out_dir}")
    print("Keep it next to the original so the shared files/ media directory is found.")
    print(f"New key (canonical):     {new_aep}")
    print(f"New key (Signal style):  {display_aep(new_aep)}")


def _cmd_verify(args):
    """Diagnose a local archive without fully decrypting: is the AEP correct?"""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    from .keys import derive_backup_key, derive_message_backup_key
    from .local import find_snapshot, recover_backup_id

    aep = _get_aep(args)  # normalized: whitespace stripped, #/= un-swapped, lowercased
    charset = set("abcdefghijklmnopqrstuvwxyz0123456789")
    offenders = sorted(set(aep) - charset)
    print(f"normalized length: {len(aep)}  (need 64)  |  non-alphanumeric: {offenders}")
    if len(aep) != AEP_LEN or offenders:
        print("=> Still not a canonical AEP after normalization; check the key.")
        return
    backup_key = derive_backup_key(aep)

    path = Path(args.source)
    if not path.is_dir():
        sys.exit("verify currently supports a local archive folder (the snapshot dir or its parent)")
    snapshot = find_snapshot(path)
    backup_id = recover_backup_id((snapshot / "metadata").read_bytes(), backup_key)
    print(f"BackupId from metadata:  {backup_id.hex()}")

    data = (snapshot / "main").read_bytes()
    if has_forward_secrecy(data):
        print("main: has forward-secrecy magic (unexpected for a local archive)")
        return
    key = derive_message_backup_key(backup_key, backup_id)
    iv, first_block = data[:16], data[16:32]
    plain0 = Cipher(algorithms.AES(key.aes_key), modes.CBC(iv)).decryptor().update(first_block)
    gzip_ok = plain0[:3] == b"\x1f\x8b\x08"
    print(f"main decrypts to gzip header: {gzip_ok} "
          f"({'AEP is CORRECT — key works' if gzip_ok else 'AEP is WRONG for this backup'})")


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="signal-backup", description="Decrypt a new-format (v2) Signal Android backup."
    )
    sub = parser.add_subparsers(dest="cmd", required=True)
    for name, handler, help_ in (
        ("decrypt", _cmd_decrypt, "decrypt to the raw plaintext frame stream (debug)"),
        ("json", _cmd_json, "export chats as JSON (manifest + one file per chat)"),
        ("html", _cmd_html, "render a browsable HTML archive"),
        ("verify", _cmd_verify, "diagnose whether the AEP is correct for the archive"),
        ("change-key", _cmd_change_key, "re-encrypt under a fresh random AEP (for testing)"),
    ):
        p = sub.add_parser(name, help=help_)
        p.add_argument("source", help="local archive folder (the snapshot dir or its parent)")
        p.add_argument("--aep", help="Account Entropy Pool (else $SIGNAL_AEP or prompt)")
        p.add_argument("--no-media", action="store_true", help="skip decrypting attachments (html)")
        p.add_argument("-o", "--output",
                       help="output file (decrypt) or directory (json/html/change-key)")
        p.set_defaults(func=handler)

    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
