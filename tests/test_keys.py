"""Known-answer tests transcribed from libsignal's own unit tests.

Vectors from vendor/libsignal:
  account-keys/src/backup.rs  (backup_key_known_from_account_entropy)
  message-backup/src/key.rs   (message_backup_key_legacy)

If any of these fail after a submodule bump, a derivation constant changed upstream.
"""

from signal_backup_decrypt.keys import (
    AEP_LEN,
    derive_backup_key,
    derive_message_backup_key,
    display_aep,
    generate_aep,
    normalize_aep,
)

AEP = "dtjs858asj6tv0jzsqrsmj0ubp335pisj98e9ssnss8myoc08drhtcktyawvx45l"

EXPECTED_BACKUP_KEY = bytes.fromhex("ea26a2ddb5dba5ef9e34e1b8dea1f5ae7f255306a6d2d883e542306eaa9fe985")
# The BackupId matching key.rs's test account; for a local archive it is recovered
# from the encrypted `metadata` file (see test_local.py) rather than derived.
BACKUP_ID = bytes.fromhex("8a624fbc45379043f39f1391cddc5fe8")
# key.rs FAKE_MESSAGE_BACKUP_KEY_LEGACY
EXPECTED_HMAC = bytes.fromhex("f425e22a607c529717e1e1b29f9fe139f9d1c7e7d01e371c7753c544a3026649")
EXPECTED_AES = bytes.fromhex("e143f4ad5668d8bfed2f88562f0693f53bda2c0e55c9d71730f30e24695fd6df")


def test_backup_key():
    assert derive_backup_key(AEP) == EXPECTED_BACKUP_KEY


def test_backup_key_tolerates_display_form():
    # Reproduce Signal's exact display transform: uppercase, then O->#, 0->=, grouped in 4s.
    display = AEP.upper().replace("O", "#").replace("0", "=")
    grouped = "  ".join(display[i : i + 4] for i in range(0, len(display), 4)) + "\n"
    assert "#" in display and "=" in display  # AEP contains 'o' and '0', so both swaps are exercised
    assert derive_backup_key(grouped) == EXPECTED_BACKUP_KEY


def test_message_backup_key():
    k = derive_message_backup_key(EXPECTED_BACKUP_KEY, BACKUP_ID)
    assert (k.hmac_key, k.aes_key) == (EXPECTED_HMAC, EXPECTED_AES)


def test_display_aep_inverts_normalize():
    assert normalize_aep(display_aep(AEP)) == AEP


def test_generate_aep_shape():
    aep = generate_aep()
    assert len(aep) == AEP_LEN
    assert set(aep) <= set("abcdefghijklmnopqrstuvwxyz0123456789")
    assert generate_aep() != aep  # vanishingly unlikely to collide
