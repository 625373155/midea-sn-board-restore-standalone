import subprocess
import tempfile
import unittest
from pathlib import Path

import public_release_check as release_check


def git(repository: Path, *arguments: str, input_bytes: bytes | None = None) -> bytes:
    completed = subprocess.run(
        ["git", *arguments],
        cwd=repository,
        input=input_bytes,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if completed.returncode:
        raise AssertionError(completed.stderr.decode("utf-8", errors="replace"))
    return completed.stdout


class PublicReleaseCheckTests(unittest.TestCase):
    def test_current_source_has_empty_embedded_history(self) -> None:
        self.assertEqual(release_check._check_empty_immutable_events(), [])

    def test_nul_and_identity_in_path_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "binary-nul.txt").write_bytes(b"synthetic\x00binary")
            leaked_name = ("7" * 22) + ".txt"
            (root / leaked_name).write_text("placeholder", encoding="utf-8")
            issues = release_check._scan_worktree(root)
            self.assertTrue(any("NUL/binary content" in issue for issue in issues))
            self.assertTrue(any("non-allowlisted 21-32 digit sequence" in issue for issue in issues))

    def test_all_referenced_history_and_metadata_are_scanned(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            git(root, "init", "-q")
            git(root, "config", "user.name", "Synthetic Test")
            git(root, "config", "user.email", "synthetic@example.invalid")

            leaked_identity = "7" * 22
            leaked_service = "midea_test_" + ("b" * 12)
            credential = "ghp_" + ("A" * 24)
            (root / "source.txt").write_text("synthetic source", encoding="utf-8")
            git(root, "add", "source.txt")
            git(root, "commit", "-q", "-m", "synthetic baseline")

            (root / "old-private.txt").write_text(leaked_identity, encoding="utf-8")
            (root / "binary-nul.txt").write_bytes(b"a\x00b")
            git(root, "add", "old-private.txt", "binary-nul.txt")
            git(root, "commit", "-q", "-m", "old " + leaked_identity)
            git(root, "tag", "-a", "audit-tag", "-m", credential + " " + leaked_service)
            git(root, "branch", "audit-" + leaked_identity)

            blob = git(root, "hash-object", "-w", "--stdin", input_bytes=b"source.txt").decode().strip()
            tree_line = f"120000 blob {blob}\tlinked\n".encode("utf-8")
            tree = git(root, "mktree", input_bytes=tree_line).decode().strip()
            commit = git(root, "commit-tree", tree, "-m", "synthetic symlink audit").decode().strip()
            git(root, "update-ref", "refs/heads/symlink-audit", commit)

            issues = release_check._scan_referenced_history(root)
            self.assertTrue(any("non-allowlisted 21-32 digit sequence" in issue for issue in issues))
            self.assertTrue(any("possible GitHub credential" in issue for issue in issues))
            self.assertTrue(any("non-allowlisted Midea service-hotspot identity" in issue for issue in issues))
            self.assertTrue(any("NUL/binary content" in issue for issue in issues))
            self.assertTrue(any("symlinks are forbidden" in issue for issue in issues))
            self.assertTrue(any(issue.startswith("git-commit:") for issue in issues))
            self.assertTrue(any(issue.startswith("git-tag:") for issue in issues))
            self.assertTrue(any(issue.startswith("git-ref:") for issue in issues))


if __name__ == "__main__":
    unittest.main()
