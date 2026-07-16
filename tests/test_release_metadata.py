import unittest
from pathlib import Path

from midea_sn_restore import __repository__, __version__, generator, validator


ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = "https://github.com/625373155/midea-sn-board-restore-standalone"


class ReleaseMetadataTests(unittest.TestCase):
    def test_public_release_metadata_is_consistent(self) -> None:
        self.assertEqual(__version__, "1.0.0")
        self.assertEqual((ROOT / "VERSION").read_text(encoding="utf-8").strip(), __version__)
        self.assertEqual(__repository__, REPOSITORY)

        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        security = (ROOT / "SECURITY.md").read_text(encoding="utf-8")
        self.assertIn(REPOSITORY, readme)
        self.assertIn(REPOSITORY, changelog)
        self.assertIn(REPOSITORY, security)
        self.assertIn("v1.0.0", readme)
        self.assertIn("## [1.0.0]", changelog)

    def test_component_version_is_documented_and_validator_locked(self) -> None:
        self.assertEqual(generator.GENERATOR_VERSION, "1.3.0")
        self.assertEqual(validator.EXPECTED_GENERATOR_VERSION, generator.GENERATOR_VERSION)
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("生成器组件版本是 `1.3.0`", readme)

    def test_no_license_file_is_claimed_or_present(self) -> None:
        license_files = [path for path in ROOT.iterdir() if path.is_file() and path.name.upper().startswith("LICENSE")]
        self.assertEqual(license_files, [])
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("没有 `LICENSE` 文件", readme)


if __name__ == "__main__":
    unittest.main()
