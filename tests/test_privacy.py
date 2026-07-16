import re
import unittest
from pathlib import Path

from midea_sn_restore import generator, validator


ROOT = Path(__file__).resolve().parents[1]
ALLOWED_SN = "1234567890123456789012"
ALLOWED_APP_DISPLAY = "00000012345678901234567890120000"
ALLOWED_SSID = "midea_test_a1b2c3d4e5f6"


def public_text_files() -> list[Path]:
    allowed_suffixes = {".py", ".json", ".md", ".yml", ".yaml", ".cmd", ".tmpl", ".txt"}
    return [
        path
        for path in ROOT.rglob("*")
        if path.is_file()
        and path.suffix.lower() in allowed_suffixes
        and ".git" not in path.parts
        and "__pycache__" not in path.parts
    ]


class PublicPrivacyTests(unittest.TestCase):
    def test_no_embedded_incident_history(self) -> None:
        self.assertEqual(generator.IMMUTABLE_PRIOR_EVENTS, ())

    def test_only_allowlisted_complete_numeric_identity(self) -> None:
        found: set[str] = set()
        for path in public_text_files():
            text = path.read_text(encoding="utf-8-sig")
            found.update(re.findall(r"(?<![0-9])[0-9]{22}(?![0-9])", text))
        self.assertEqual(found, {ALLOWED_SN})

    def test_only_allowlisted_app_example(self) -> None:
        found: set[str] = set()
        for path in public_text_files():
            text = path.read_text(encoding="utf-8-sig")
            found.update(re.findall(r"(?<![0-9])[0-9]{32}(?![0-9])", text))
        self.assertEqual(found, {ALLOWED_APP_DISPLAY})

    def test_only_allowlisted_service_identity(self) -> None:
        found: set[str] = set()
        for path in public_text_files():
            text = path.read_text(encoding="utf-8-sig")
            found.update(re.findall(r"midea_test_[0-9A-Fa-f]{12}", text))
        self.assertEqual(found, {ALLOWED_SSID})

    def test_model_allowlists_match_and_are_closed(self) -> None:
        expected = ("KFR-26G/WXAA2@",)
        self.assertEqual(generator.COMPATIBLE_MODELS, expected)
        self.assertEqual(validator.COMPATIBLE_MODELS, expected)


if __name__ == "__main__":
    unittest.main()
