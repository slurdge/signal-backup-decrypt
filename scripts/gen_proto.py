"""Regenerate signal_backup_decrypt/proto/*_pb2.py from the vendored libsignal .proto.

Run after bumping the vendor/libsignal submodule:  uv run python scripts/gen_proto.py
Requires the dev dependency grpcio-tools (protoc is bundled with it).
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PROTO_SRC = ROOT / "vendor/libsignal/rust/message-backup/src/proto"
OUT = ROOT / "signal_backup_decrypt/proto"


def main() -> int:
    if not (PROTO_SRC / "backup.proto").exists():
        sys.exit(f"Missing {PROTO_SRC / 'backup.proto'} — did you init the submodule?")
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "__init__.py").touch()
    cmd = [
        sys.executable, "-m", "grpc_tools.protoc",
        f"--proto_path={PROTO_SRC}",
        f"--python_out={OUT}",
        f"--pyi_out={OUT}",  # typed stubs: readable message defs + IDE go-to-definition
        "backup.proto",
    ]
    print(" ".join(cmd))
    return subprocess.run(cmd, check=True).returncode


if __name__ == "__main__":
    raise SystemExit(main())
