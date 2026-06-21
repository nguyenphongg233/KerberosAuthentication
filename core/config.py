"""Runtime configuration helpers.

The project intentionally avoids an extra python-dotenv dependency. This small
loader supports the .env subset needed by the demo: KEY=value lines, optional
single/double quotes, comments, and "export KEY=value".
"""

from __future__ import annotations

import os
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DOTENV_PATH = PROJECT_ROOT / ".env"


def _clean_value(raw_value: str) -> str:
    value = raw_value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        value = value[1:-1]
        if raw_value.strip().startswith('"'):
            value = (
                value.replace(r"\n", "\n")
                .replace(r"\r", "\r")
                .replace(r"\t", "\t")
                .replace(r"\"", '"')
                .replace(r"\\", "\\")
            )
        return value

    if " #" in value:
        value = value.split(" #", 1)[0].rstrip()
    return value


def load_dotenv(env_path: str | os.PathLike[str] | None = None, *, override: bool = False) -> int:
    """Load KEY=value pairs from a .env file into os.environ.

    Existing environment variables win by default so tests, subprocess env, and
    shell-provided values remain authoritative.
    """
    path = Path(env_path) if env_path is not None else DEFAULT_DOTENV_PATH
    if not path.exists():
        return 0

    loaded = 0
    for raw_line in path.read_text(encoding="utf-8-sig").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export "):].strip()
        if "=" not in line:
            continue

        key, raw_value = line.split("=", 1)
        key = key.strip()
        if not key or not key.replace("_", "").isalnum() or key[0].isdigit():
            continue
        if override or key not in os.environ:
            os.environ[key] = _clean_value(raw_value)
            loaded += 1
    return loaded
