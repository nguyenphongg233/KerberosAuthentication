"""Runtime .env configuration loader tests."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from core.config import load_dotenv


class DotEnvConfigTests(unittest.TestCase):
    def test_load_dotenv_reads_values_and_preserves_existing_environment(self) -> None:
        old_env = dict(os.environ)
        try:
            with tempfile.TemporaryDirectory(prefix="krb-dotenv-") as temp_dir:
                env_path = Path(temp_dir) / ".env"
                env_path.write_text(
                    "\n".join(
                        [
                            "# comment",
                            "KRB_TEST_DOTENV_VALUE=from_file",
                            'KRB_TEST_QUOTED="quoted value"',
                            "KRB_TEST_COMMENT=kept # inline comment",
                            "export KRB_TEST_EXPORT=exported",
                            "KRB_TEST_EXISTING=from_file",
                        ]
                    ),
                    encoding="utf-8",
                )

                os.environ["KRB_TEST_EXISTING"] = "from_shell"
                loaded = load_dotenv(env_path)

                self.assertEqual(4, loaded)
                self.assertEqual("from_file", os.environ["KRB_TEST_DOTENV_VALUE"])
                self.assertEqual("quoted value", os.environ["KRB_TEST_QUOTED"])
                self.assertEqual("kept", os.environ["KRB_TEST_COMMENT"])
                self.assertEqual("exported", os.environ["KRB_TEST_EXPORT"])
                self.assertEqual("from_shell", os.environ["KRB_TEST_EXISTING"])
        finally:
            os.environ.clear()
            os.environ.update(old_env)


if __name__ == "__main__":
    unittest.main(verbosity=2)
