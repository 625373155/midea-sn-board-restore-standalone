from __future__ import annotations

"""Fail closed when a public release contains private identities or artifacts."""

import ast
import json
import re
import subprocess
import sys
from pathlib import Path


REPOSITORY = Path(__file__).resolve().parent
GENERATOR = REPOSITORY / "midea_sn_restore" / "generator.py"
CORPUS = REPOSITORY / "midea_sn_restore" / "test_vectors.json"

SYNTHETIC_SN = "1234567890123456789012"
SYNTHETIC_SSID_HEX = "a1b2c3d4e5f6"
ALLOWED_LONG_ASCII_DIGITS = {
    SYNTHETIC_SN,
    SYNTHETIC_SN[:-1],
    SYNTHETIC_SN + "3",
    "000000" + SYNTHETIC_SN + "0000",
}
ALLOWED_LONG_FULLWIDTH_DIGITS = {
    SYNTHETIC_SN.translate(str.maketrans("0123456789", "０１２３４５６７８９"))
}
ALLOWED_SERVICE_SUFFIXES = {
    SYNTHETIC_SSID_HEX,
    SYNTHETIC_SSID_HEX[:-1],
    SYNTHETIC_SSID_HEX + "0",
}
FORBIDDEN_FILE_SUFFIXES = {
    ".gif",
    ".jpeg",
    ".jpg",
    ".jsonl",
    ".log",
    ".pdf",
    ".png",
    ".webp",
    ".zip",
}
TEXT_SUFFIXES = {
    "",
    ".cmd",
    ".cfg",
    ".gitattributes",
    ".gitignore",
    ".ini",
    ".json",
    ".md",
    ".ps1",
    ".py",
    ".toml",
    ".txt",
    ".tmpl",
    ".yaml",
    ".yml",
}
FALLBACK_IGNORED_PARTS = {".git", ".pytest_cache", ".venv", "__pycache__", "venv"}

LONG_ASCII_DIGITS_RE = re.compile(r"(?<![0-9])[0-9]{21,32}(?![0-9])", re.ASCII)
LONG_FULLWIDTH_DIGITS_RE = re.compile(r"(?<![０-９])[０-９]{21,32}(?![０-９])")
SERVICE_ID_RE = re.compile(r"midea_test\s*_?\s*((?:[0-9A-Fa-f]\s*){8,20})", re.ASCII)
TOKEN_RE = re.compile(
    r"(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})",
    re.ASCII,
)
ABSOLUTE_USER_PATH_RE = re.compile(r"[A-Za-z]:[\\/]Users[\\/][^\\/\s]+[\\/]", re.IGNORECASE)


class ReleaseCheckError(RuntimeError):
    pass


def _text_from_bytes(data: bytes, label: str) -> str:
    if b"\x00" in data:
        raise ReleaseCheckError(f"NUL/binary content is forbidden in a declared text file: {label}")
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ReleaseCheckError(f"non-UTF-8 text is not allowed in public source: {label}") from exc


def _scan_text(text: str, label: str) -> list[str]:
    issues: list[str] = []
    for match in LONG_ASCII_DIGITS_RE.finditer(text):
        if match.group(0) not in ALLOWED_LONG_ASCII_DIGITS:
            issues.append(f"{label}: non-allowlisted 21-32 digit sequence")
    for match in LONG_FULLWIDTH_DIGITS_RE.finditer(text):
        if match.group(0) not in ALLOWED_LONG_FULLWIDTH_DIGITS:
            issues.append(f"{label}: non-allowlisted full-width digit sequence")
    for match in SERVICE_ID_RE.finditer(text):
        suffix = re.sub(r"\s+", "", match.group(1)).lower()
        if suffix not in ALLOWED_SERVICE_SUFFIXES:
            issues.append(f"{label}: non-allowlisted Midea service-hotspot identity")
    if TOKEN_RE.search(text):
        issues.append(f"{label}: possible GitHub credential")
    if ABSOLUTE_USER_PATH_RE.search(text):
        issues.append(f"{label}: absolute Windows user path")
    return issues


def _git_output(repository: Path, *arguments: str) -> bytes:
    return subprocess.run(
        ["git", *arguments],
        cwd=repository,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).stdout


def _candidate_worktree_paths(repository: Path) -> list[Path]:
    try:
        raw = _git_output(
            repository, "ls-files", "-z", "--cached", "--others", "--exclude-standard"
        )
    except (FileNotFoundError, subprocess.CalledProcessError):
        return sorted(
            path
            for path in repository.rglob("*")
            if not any(part in FALLBACK_IGNORED_PARTS for part in path.relative_to(repository).parts)
            and (path.is_file() or path.is_symlink())
        )
    return sorted(
        repository / value.decode("utf-8")
        for value in raw.split(b"\x00")
        if value
    )


def _scan_source_entry(relative: str, data: bytes | None, *, prefix: str) -> list[str]:
    issues = _scan_text(relative, f"{prefix}-path:{relative}")
    path = Path(relative)
    if path.suffix.lower() in FORBIDDEN_FILE_SUFFIXES or path.name == "TARGET.json":
        issues.append(f"{prefix}:{relative}: private/generated artifact type is forbidden")
        return issues
    if path.suffix.lower() not in TEXT_SUFFIXES and not path.name.startswith("."):
        issues.append(f"{prefix}:{relative}: unreviewed file type")
        return issues
    if data is None:
        return issues
    try:
        text = _text_from_bytes(data, f"{prefix}:{relative}")
    except ReleaseCheckError as exc:
        issues.append(str(exc))
    else:
        issues.extend(_scan_text(text, f"{prefix}:{relative}"))
    return issues


def _scan_worktree(repository: Path = REPOSITORY) -> list[str]:
    issues: list[str] = []
    for path in _candidate_worktree_paths(repository):
        relative = path.relative_to(repository).as_posix()
        if path.is_symlink():
            issues.extend(_scan_text(relative, f"worktree-path:{relative}"))
            issues.append(f"worktree:{relative}: symlinks are forbidden")
            continue
        try:
            data = path.read_bytes()
        except OSError as exc:
            issues.append(f"worktree:{relative}: cannot read file: {exc}")
            continue
        issues.extend(_scan_source_entry(relative, data, prefix="worktree"))
    return issues


def _scan_referenced_history(repository: Path = REPOSITORY) -> list[str]:
    """Scan every commit reachable from every ref, plus all ref/tag metadata."""

    try:
        revisions = _git_output(repository, "rev-list", "--all").decode("ascii").splitlines()
    except (FileNotFoundError, subprocess.CalledProcessError, UnicodeDecodeError):
        return []

    issues: list[str] = []
    for revision in revisions:
        try:
            entries = _git_output(repository, "ls-tree", "-rz", "--full-tree", revision)
        except subprocess.CalledProcessError as exc:
            issues.append(f"git:{revision[:12]}: tree scan failed: {exc}")
            continue
        for entry in entries.split(b"\x00"):
            if not entry:
                continue
            try:
                metadata, raw_name = entry.split(b"\t", 1)
                mode, object_type, object_id = metadata.decode("ascii").split(" ", 2)
                name = raw_name.decode("utf-8")
            except (UnicodeDecodeError, ValueError):
                issues.append(f"git:{revision[:12]}: undecodable tree entry")
                continue
            issues.extend(_scan_text(name, f"git-path:{revision[:12]}:{name}"))
            if mode == "120000":
                issues.append(f"git:{revision[:12]}:{name}: symlinks are forbidden")
                continue
            if object_type != "blob":
                issues.append(f"git:{revision[:12]}:{name}: unexpected tree object {object_type}")
                continue
            try:
                data = _git_output(repository, "cat-file", "blob", object_id)
            except subprocess.CalledProcessError as exc:
                issues.append(f"git:{revision[:12]}:{name}: blob read failed: {exc}")
                continue
            issues.extend(
                _scan_source_entry(name, data, prefix=f"git:{revision[:12]}")
            )

    try:
        commit_data = _git_output(repository, "log", "--all", "--format=%H%x00%B%x00")
        commit_parts = commit_data.decode("utf-8").split("\x00")
        for index in range(0, len(commit_parts) - 1, 2):
            revision = commit_parts[index].strip()
            message = commit_parts[index + 1]
            if revision:
                issues.extend(_scan_text(message, f"git-commit:{revision[:12]}"))

        refs_data = _git_output(
            repository, "for-each-ref", "--format=%(refname)%00%(contents)%00"
        ).decode("utf-8")
        ref_parts = refs_data.split("\x00")
        for index in range(0, len(ref_parts) - 1, 2):
            ref_name = ref_parts[index].strip()
            contents = ref_parts[index + 1]
            if not ref_name:
                continue
            issues.extend(_scan_text(ref_name, f"git-ref:{ref_name}"))
            if ref_name.startswith("refs/tags/"):
                issues.extend(_scan_text(contents, f"git-tag:{ref_name}"))
    except (subprocess.CalledProcessError, UnicodeDecodeError) as exc:
        issues.append(f"Git metadata scan failed: {exc}")
    return issues


def _check_empty_immutable_events(generator: Path = GENERATOR) -> list[str]:
    tree = ast.parse(generator.read_text(encoding="utf-8"), filename=str(generator))
    for node in tree.body:
        target_name: str | None = None
        value: ast.expr | None = None
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            target_name = node.targets[0].id
            value = node.value
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            target_name = node.target.id
            value = node.value
        if target_name == "IMMUTABLE_PRIOR_EVENTS":
            if not isinstance(value, (ast.Tuple, ast.List)) or value.elts:
                return ["generator.py: IMMUTABLE_PRIOR_EVENTS must be an empty literal"]
            return []
    return ["generator.py: IMMUTABLE_PRIOR_EVENTS declaration is missing"]


def _check_corpus(corpus_path: Path = CORPUS) -> list[str]:
    corpus = json.loads(corpus_path.read_text(encoding="utf-8"))
    issues: list[str] = []
    if corpus.get("synthetic_only") is not True:
        issues.append("test_vectors.json: synthetic_only must be true")
    for section in ("encoding_vectors", "counter_vectors"):
        for index, vector in enumerate(corpus.get(section, [])):
            if vector.get("regression_only") is not True:
                issues.append(f"test_vectors.json: {section}[{index}] lacks regression_only=true")
    if corpus.get("known_frame_vector", {}).get("regression_only") is not True:
        issues.append("test_vectors.json: known_frame_vector lacks regression_only=true")
    if corpus.get("app_evidence_example", {}).get("synthetic_only") is not True:
        issues.append("test_vectors.json: app_evidence_example lacks synthetic_only=true")
    return issues


def scan_repository(repository: Path = REPOSITORY, *, skip_history: bool = False) -> list[str]:
    issues = _scan_worktree(repository)
    if repository == REPOSITORY:
        issues.extend(_check_empty_immutable_events())
        issues.extend(_check_corpus())
    if not skip_history:
        issues.extend(_scan_referenced_history(repository))
    return sorted(set(issues))


def main() -> int:
    issues = scan_repository(skip_history="--skip-history" in sys.argv[1:])
    if issues:
        print("PUBLIC_RELEASE_CHECK_FAILED", file=sys.stderr)
        for issue in issues:
            print(f"- {issue}", file=sys.stderr)
        return 2
    print("public release check: PASS (synthetic identities only)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
