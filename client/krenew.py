"""Module wrapper for `python -m client.krenew`."""

from __future__ import annotations

import sys

from client.kerberos_cli import main


if __name__ == "__main__":
    raise SystemExit(main(["renew", *sys.argv[1:]]))
