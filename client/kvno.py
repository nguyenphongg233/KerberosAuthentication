"""Module wrapper for `python -m client.kvno`."""

from __future__ import annotations

import sys

from client.kerberos_cli import main


if __name__ == "__main__":
    raise SystemExit(main(["kvno", *sys.argv[1:]]))
