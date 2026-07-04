# signal-backup-decrypt

## Foreword

This project served as a test of capacities of LLM, namely at the time of writing, Fable.
Thus, LLM was involved in the writing of the tool. Still, all aspects have been check by an human and the project works on real data.

## Description

Decrypt a **new-format ("Signal Backups" / v2)** Signal Android backup offline and export it
as a browsable HTML archive or as JSON. This targets the format keyed off your **Account Entropy
Pool** (recovery key) — *not* the classic 30-digit-passphrase `.backup` file.

The cryptography is transcribed directly from Signal's own [libsignal](https://github.com/signalapp/libsignal)
(vendored as a git submodule under `vendor/`) so it can be re-verified when the format changes,
rather than trusting a third-party description. Key derivation and envelope layout come from
`rust/message-backup` and `rust/account-keys`.

The input is a **local archive folder** — a `signal-backup-YYYY-...` snapshot folder (containing
`main`, `metadata`, `files`), or a parent folder holding one. This is what Signal Android writes
for an on-device backup. Point the tool at the folder; everything is recovered offline from the
encrypted `metadata` file plus your **Account Entropy Pool** (the 64-character recovery key).
Signal shows the AEP uppercased and in space-separated groups; the tool normalizes that (strips
spaces, lowercases), so paste it however it's displayed.

## Usage

```bash
uv sync
# Point at the archive folder — open out/index.html in a browser:
uv run signal-backup html data -o out
uv run signal-backup json data -o out

# Re-runs reuse media already in out/media (big time saver); --force-files re-decrypts:
uv run signal-backup html data -o out --force-files

# Raw decrypted protobuf frame stream (debugging):
uv run signal-backup decrypt data -o frames.bin

# Re-encrypt under a fresh throwaway key and print it, so day-to-day testing never
# touches the real recovery key. Writes <snapshot>-rekeyed next to the original
# (media is shared, so only metadata+main are rewritten):
uv run signal-backup change-key data
```

The AEP is read from the `SIGNAL_AEP` environment variable, else a hidden interactive prompt.

## How the encryption works (findings)

All of the following was transcribed from source (`vendor/libsignal` at the pinned commit, plus
Signal-Android's `lib/archive`, `backup/v2/local`, and `core/models-jvm`), and pinned by the tests.

**Key derivation** — every step is HKDF-SHA256:

```
AEP (64-char recovery key, used verbatim as HKDF IKM)
 └─ BackupKey(32)   = HKDF(salt=∅, info="20240801_SIGNAL_BACKUP_KEY")
      ├─ localMetadataKey(32)  = HKDF(BackupKey, info="20241011_SIGNAL_LOCAL_BACKUP_METADATA_KEY")
      └─ MessageBackupKey(64)  = HKDF(BackupKey, info=DST ‖ BackupId)
              = hmacKey(32) ‖ aesKey(32)
              DST = "20241007_SIGNAL_BACKUP_ENCRYPT_MESSAGE_BACKUP:"
              BackupId(16) recovered from the encrypted `metadata` file (below)
```

**The recovery key (AEP)** — the canonical alphabet is digits + lowercase (`0-9a-z`) only. Signal
*displays* it uppercased, grouped in 4s, and with two characters swapped for legibility
(`CHARACTER_DISPLAY_MAP`: letter `O`→`#`, digit `0`→`=`). To use a pasted key you must reverse that:
strip whitespace, map `#`→`O` and `=`→`0`, then lowercase.

**Recovering the BackupId (fully offline)** — a snapshot folder holds `metadata`, `main`, `files`.
The 36-byte `metadata` is a protobuf `{version, EncryptedBackupId{iv(12), encryptedId(16)}}`; the
BackupId is recovered by AES-256-CTR-decrypting `encryptedId` with `localMetadataKey` (12-byte nonce
+ 32-bit counter). Because `localMetadataKey` comes from the BackupKey alone, nothing beyond the
AEP is needed.

**The `main` message file** — layout is `IV(16) ‖ AES-256-CBC(aesKey) ‖ HMAC-SHA256(hmacKey)(32)`,
where the HMAC covers `IV‖ciphertext`. Decrypting yields a **gzip** stream (stop at the gzip EOF;
ignore trailing padding) whose plaintext is varint-length-delimited protobufs: one `BackupInfo`
then a stream of `Frame` (recipients, chats, chatItems, …).

**Attachments** — the message file holds only metadata; bytes live under `files/<name[:2]>/<name>`
with `name = hex(sha256(plaintextHash ‖ localKey))`, both from the message's `FilePointer.locatorInfo`.
Each file is Signal's attachment cipher (`AttachmentCipherOutputStream`): 64-byte `localKey` split
into AES(32)+MAC(32), layout `IV(16) ‖ AES-256-CBC/PKCS5 ‖ HMAC-SHA256(32)` with the MAC over
`IV‖ciphertext`; the plaintext is zero-padded to a bucket size, so decrypt and truncate to the
`FilePointer` plaintext `size`.

## Known limitations

- **Media** is decrypted from the sibling `files/` directory and rendered inline
  (images/video/audio) or linked (other files); pass `--no-media` to skip.
- **Contact and group photos are not in the backup at all** — the frames carry only an
  `avatarColor` enum (plus the profile key Signal uses to refetch photos from the CDN after a
  restore). The HTML export therefore renders the app's colored-initial avatars, using the stored
  color or, when unset, Signal's documented fallback (`AvatarColorHash`: first byte of
  SHA-256(contact id) modulo the palette).
- Rich message types (payments, gift badges, polls, view-once) show as labeled placeholders. Text,
  attachments, stickers, quotes, reactions, link previews, and common system messages render.

## Development

```bash
uv run pytest                      # offline: KATs from libsignal + envelope round-trip
uv run python scripts/gen_proto.py # regenerate backup_pb2.py(+.pyi) after bumping the submodule
```

The generated `backup_pb2.py` is an opaque serialized descriptor; the readable versions are the
schema itself (`vendor/libsignal/rust/message-backup/src/proto/backup.proto`) and the generated
`backup_pb2.pyi` stub, which is what IDEs use for go-to-definition on `backup_pb2.Recipient` etc.

`tests/test_keys.py` pins the whole derivation chain to libsignal's own known-answer vectors, so a
CI-style `pytest` run tells you immediately if an upstream constant changed.
