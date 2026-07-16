from __future__ import annotations

"""Create one immutable, identity-bound Midea body-SN restore package.

This program is deliberately an offline generator.  It imports no networking
module, never joins Wi-Fi, never opens the generated PowerShell program, and
never sends an appliance frame.  Its output still contains a potentially
state-changing write path, so generation is gated by explicit ownership,
source, and new-physical-board confirmations and by an append-only event log.
"""

import argparse
import hashlib
import json
import os
import re
import shutil
import sys
import unicodedata
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from .protocol import encode_sn, target_vectors, validate_body_sn


GENERATOR_VERSION = "1.3.0"
SCHEMA_VERSION = 1
SERVICE_SSID_RE = re.compile(r"midea_test_[0-9A-Fa-f]{12}\Z", re.ASCII)
MODEL_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9@._+()/\-]{0,63}\Z", re.ASCII)
TOKEN_RE = re.compile(r"@@([A-Z][A-Z0-9_]*)@@", re.ASCII)
INCIDENT_RE = re.compile(
    r"(?:[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}|legacy-[a-z0-9-]{4,80})\Z",
    re.ASCII,
)
SOURCE_CHOICES = ("customer-service", "original-label", "old-app", "old-board")
COMPATIBLE_MODELS = ("KFR-26G/WXAA2@",)
EVIDENCE_HASH_VERSION = "nfkc-casefold-whitespace-v1"
TEMPLATE_DIRECTORY = Path(__file__).resolve().parent / "templates"
PROJECT_DIRECTORY = Path(__file__).resolve().parents[1]

# Public source releases never embed customer/device history.  Real incident
# history is append-only state on the owner's computer, outside this repository.
IMMUTABLE_PRIOR_EVENTS: tuple[dict[str, Any], ...] = ()


class GenerationError(RuntimeError):
    """A fail-closed package-generation error."""


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _device_key(sn: str, normalized_ssid: str) -> str:
    return _sha256_bytes(f"{sn}|{normalized_ssid}".encode("ascii"))


def _normalize_ssid(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9]", "", value).lower()


def _validate_ssid(value: str) -> tuple[str, str]:
    if not isinstance(value, str) or SERVICE_SSID_RE.fullmatch(value) is None:
        raise GenerationError("service SSID must exactly match midea_test_<12 hexadecimal characters>")
    return value, _normalize_ssid(value)


def _validate_model(value: str) -> str:
    if not isinstance(value, str) or MODEL_RE.fullmatch(value) is None:
        raise GenerationError(
            "model must be 1-64 safe ASCII characters (letters, digits, @ . _ + ( ) / or -)"
        )
    if value not in COMPATIBLE_MODELS:
        raise GenerationError(
            "model is outside the verified compatibility allowlist; this release supports only "
            + ", ".join(COMPATIBLE_MODELS)
        )
    return value


def _validate_evidence(value: str, label: str) -> str:
    if not isinstance(value, str) or not 3 <= len(value) <= 240:
        raise GenerationError(f"{label} must contain 3-240 characters")
    if "\r" in value or "\n" in value or any(not char.isprintable() for char in value):
        raise GenerationError(f"{label} must be one printable line")
    if value != value.strip():
        raise GenerationError(f"{label} must not contain leading or trailing whitespace")
    return value


def _normalize_evidence_for_history(value: str) -> str:
    """Canonicalize evidence only for repeat-event comparison.

    The original evidence remains in the manifest.  The versioned history hash
    prevents casing, compatibility-character, or whitespace-only rewrites from
    being presented as fresh evidence for another physical-board incident.
    """

    normalized = unicodedata.normalize("NFKC", value).casefold()
    return re.sub(r"\s+", " ", normalized).strip()


def _validate_bssid(value: str | None) -> str | None:
    if value is None or value == "":
        return None
    if not isinstance(value, str) or re.fullmatch(
        r"(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}", value, re.ASCII
    ) is None:
        raise GenerationError("BSSID must contain six hexadecimal octets separated by ':' or '-'")
    octets = re.split(r"[:-]", value)
    normalized = ":".join(octet.lower() for octet in octets)
    if normalized in {"00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF"}:
        raise GenerationError("all-zero and broadcast BSSIDs are not valid device evidence")
    first = int(octets[0], 16)
    if first & 1:
        raise GenerationError("multicast BSSID is not valid device evidence")
    return normalized


def _local_state_directory() -> Path:
    if os.name == "nt":
        # Resolve FOLDERID_LocalAppData through the Windows Known Folder API.
        # Do not trust the process LOCALAPPDATA environment variable: changing
        # it must not hide prior generation history on the same Windows user.
        import ctypes
        from ctypes import wintypes

        class _Guid(ctypes.Structure):
            _fields_ = (
                ("Data1", ctypes.c_uint32),
                ("Data2", ctypes.c_uint16),
                ("Data3", ctypes.c_uint16),
                ("Data4", ctypes.c_ubyte * 8),
            )

        folder_id = _Guid.from_buffer_copy(uuid.UUID("f1b32785-6fba-4fcf-9d55-7b8e7f157091").bytes_le)
        result_path = ctypes.c_wchar_p()
        shell32 = ctypes.WinDLL("shell32", use_last_error=True)
        ole32 = ctypes.WinDLL("ole32", use_last_error=True)
        shell32.SHGetKnownFolderPath.argtypes = (
            ctypes.POINTER(_Guid),
            wintypes.DWORD,
            wintypes.HANDLE,
            ctypes.POINTER(ctypes.c_wchar_p),
        )
        shell32.SHGetKnownFolderPath.restype = ctypes.c_long
        ole32.CoTaskMemFree.argtypes = (ctypes.c_void_p,)
        status = shell32.SHGetKnownFolderPath(
            ctypes.byref(folder_id), 0, None, ctypes.byref(result_path)
        )
        if status != 0 or not result_path.value:
            raise GenerationError(
                f"Windows Known Folder lookup for LocalAppData failed with HRESULT 0x{status & 0xFFFFFFFF:08X}"
            )
        try:
            root = Path(result_path.value).resolve()
        finally:
            ole32.CoTaskMemFree(ctypes.cast(result_path, ctypes.c_void_p))
        return root / "MideaSnBoardRestore" / "generator"

    # Deterministic development fallback for non-Windows static tests only.
    return Path.home().resolve() / ".local" / "share" / "MideaSnBoardRestore" / "generator"


def _read_history(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    records: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as stream:
        for line_number, raw_line in enumerate(stream, 1):
            line = raw_line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise GenerationError(
                    f"event history is malformed at line {line_number}; it was not ignored: {exc}"
                ) from exc
            if not isinstance(record, dict) or not isinstance(record.get("incidentId"), str):
                raise GenerationError(
                    f"event history line {line_number} is not a valid event object; it was not ignored"
                )
            records.append(record)
    return records


def _write_all(descriptor: int, data: bytes) -> None:
    remaining = memoryview(data)
    while remaining:
        written = os.write(descriptor, remaining)
        if written <= 0:
            raise OSError("short write while persisting a generator safety record")
        remaining = remaining[written:]


def _matching_prior_events(sn: str, normalized_ssid: str, history: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    matching: list[dict[str, Any]] = []
    for record in IMMUTABLE_PRIOR_EVENTS:
        if record["targetSn"] == sn or _normalize_ssid(record["expectedServiceSsid"]) == normalized_ssid:
            matching.append(dict(record))
    for record in history:
        if record.get("targetSn") == sn or _normalize_ssid(str(record.get("expectedServiceSsid", ""))) == normalized_ssid:
            matching.append(record)
    return matching


class _ExclusiveHistoryLock:
    """CreateNew-style lock; stale locks are never silently removed."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.file_descriptor: int | None = None

    def __enter__(self) -> "_ExclusiveHistoryLock":
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            self.file_descriptor = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError as exc:
            raise GenerationError(
                f"generator history lock already exists at {self.path}; inspect it manually and do not bypass it"
            ) from exc
        payload = {
            "pid": os.getpid(),
            "createdUtc": _utc_now(),
            "purpose": "serialize append-only Midea restore package events",
        }
        _write_all(self.file_descriptor, (json.dumps(payload, ensure_ascii=False) + "\n").encode("utf-8"))
        os.fsync(self.file_descriptor)
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        if self.file_descriptor is not None:
            os.close(self.file_descriptor)
            self.file_descriptor = None
        # This only releases the generator mutex.  It never removes an event,
        # appliance write lock, or package-side write marker.
        try:
            self.path.unlink()
        except FileNotFoundError:
            pass


def _append_history(path: Path, record: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = (json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")
    descriptor = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    try:
        _write_all(descriptor, data)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _hex_to_ps_array(value: str) -> str:
    return ", ".join(f"0x{item}" for item in value.split())


def _rendered_name(relative: Path) -> Path:
    if relative.name.endswith(".tmpl"):
        return relative.with_name(relative.name[:-5])
    return relative


def _template_replacements(
    *,
    sn: str,
    ssid: str,
    normalized_ssid: str,
    bssid: str | None,
    model: str,
    incident_id: str,
    device_key: str,
    generated_utc: str,
    sn_source: str,
) -> dict[str, str]:
    vectors = target_vectors(sn)
    write_confirmation = f"WRITE-{sn[-4:]}-{normalized_ssid[-4:].upper()}-{incident_id[:8].upper()}-ONCE"
    replacements = {
        "TARGET_SN": sn,
        "TARGET_SN_LAST4": sn[-4:],
        "TARGET_SN_MASKED": f"{sn[:6]}{'*' * 12}{sn[-4:]}",
        "TARGET_ENCODED_HEX": vectors["encoded"],
        "TARGET_ENCODED_ARRAY": _hex_to_ps_array(vectors["encoded"]),
        "EXPECTED_SSID": ssid,
        "EXPECTED_SSID_NORMALIZED": normalized_ssid,
        "EXPECTED_SSID_LAST4": normalized_ssid[-4:],
        "EXPECTED_BSSID": bssid or "",
        "EXPECTED_BSSID_REQUIRED": "$true" if bssid else "$false",
        "MODEL": model,
        "INCIDENT_ID": incident_id,
        "INCIDENT_ID_SHORT": incident_id[:8],
        "DEVICE_KEY": device_key,
        "WRITE_CONFIRMATION": write_confirmation,
        "GENERATED_UTC": generated_utc,
        "SN_SOURCE": sn_source,
        "WRITE_INNER_HEX": vectors["write_inner"],
        "WRITE_INNER_ARRAY": _hex_to_ps_array(vectors["write_inner"]),
        "WRITE_CIPHER_HEX": vectors["write_cipher"],
        "WRITE_CIPHER_ARRAY": _hex_to_ps_array(vectors["write_cipher"]),
        "QUERY1_INNER_HEX": vectors["query1_inner"],
        "QUERY1_INNER_ARRAY": _hex_to_ps_array(vectors["query1_inner"]),
        "QUERY1_CIPHER_HEX": vectors["query1_cipher"],
        "QUERY1_CIPHER_ARRAY": _hex_to_ps_array(vectors["query1_cipher"]),
        "QUERY2_INNER_HEX": vectors["query2_inner"],
        "QUERY2_INNER_ARRAY": _hex_to_ps_array(vectors["query2_inner"]),
        "QUERY2_CIPHER_HEX": vectors["query2_cipher"],
        "QUERY2_CIPHER_ARRAY": _hex_to_ps_array(vectors["query2_cipher"]),
    }
    return replacements


def _render_template_tree(destination: Path, replacements: dict[str, str]) -> list[Path]:
    if not TEMPLATE_DIRECTORY.is_dir():
        raise GenerationError(f"package template directory is missing: {TEMPLATE_DIRECTORY}")
    source_files = sorted(path for path in TEMPLATE_DIRECTORY.rglob("*") if path.is_file())
    if not source_files:
        raise GenerationError(f"package template directory is empty: {TEMPLATE_DIRECTORY}")

    written: list[Path] = []
    for source in source_files:
        if source.is_symlink():
            raise GenerationError(f"symlinked template resources are refused: {source}")
        relative = source.relative_to(TEMPLATE_DIRECTORY)
        output_relative = _rendered_name(relative)
        target = destination / output_relative
        target.parent.mkdir(parents=True, exist_ok=True)
        if source.name.endswith(".tmpl"):
            try:
                rendered = source.read_text(encoding="utf-8-sig")
            except UnicodeDecodeError as exc:
                raise GenerationError(f"text template is not valid UTF-8: {source}") from exc
            for token in sorted(set(TOKEN_RE.findall(rendered))):
                if token not in replacements:
                    raise GenerationError(f"template {relative} contains unsupported token @@{token}@@")
                rendered = rendered.replace(f"@@{token}@@", replacements[token])
            leftovers = TOKEN_RE.findall(rendered)
            if leftovers:
                raise GenerationError(f"template {relative} retained unresolved tokens: {sorted(set(leftovers))}")
            encoding = "utf-8-sig" if target.suffix.lower() == ".ps1" else "utf-8"
            target.write_text(rendered, encoding=encoding, newline="\n")
        else:
            shutil.copyfile(source, target)
        written.append(target)
    return written


def _relative_hashes(package_directory: Path, *, exclude: Iterable[str] = ()) -> dict[str, str]:
    excluded = set(exclude)
    results: dict[str, str] = {}
    for path in sorted(item for item in package_directory.rglob("*") if item.is_file()):
        relative = path.relative_to(package_directory).as_posix()
        if relative not in excluded:
            results[relative] = _sha256_file(path)
    return results


def _write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _static_render_checks(package_directory: Path, sn: str, ssid: str, write_confirmation: str) -> None:
    script = package_directory / "midea_sn_restore.ps1"
    required = (
        script,
        package_directory / "00_self_test.cmd",
        package_directory / "01_query_only.cmd",
        package_directory / "02_restore_once_and_verify.cmd",
        package_directory / "03_raw_read_only_diagnostic.cmd",
        package_directory / "04_post_write_read_only_check.cmd",
    )
    missing = [str(path.name) for path in required if not path.is_file()]
    if missing:
        raise GenerationError(f"rendered template is incomplete; missing: {', '.join(missing)}")

    script_text = script.read_text(encoding="utf-8-sig")
    for literal, label in ((sn, "target SN"), (ssid, "service SSID"), (write_confirmation, "write confirmation")):
        if literal not in script_text:
            raise GenerationError(f"rendered PowerShell is not fixed to its {label}")
    if TOKEN_RE.search(script_text):
        raise GenerationError("rendered PowerShell still contains an unresolved template token")
    if re.search(r"(?im)^\s*\[string\]\s*\$TargetSn\b", script_text):
        raise GenerationError("runtime TargetSn parameter detected; target SN must be hard-coded by generation")

    for launcher in package_directory.glob("*.cmd"):
        text = launcher.read_text(encoding="utf-8-sig")
        write_mode_count = len(re.findall(r"(?i)(?:-Mode\s+Write|\bMode=Write\b)", text))
        if launcher.name == "02_restore_once_and_verify.cmd":
            if write_mode_count != 1:
                raise GenerationError("02 restore launcher must contain exactly one Write-mode invocation")
        elif write_mode_count:
            raise GenerationError(f"read-only launcher unexpectedly contains Write mode: {launcher.name}")


def _zip_package(package_directory: Path, archive_path: Path) -> None:
    temporary = archive_path.with_name(f".{archive_path.name}.building-{uuid.uuid4().hex}")
    try:
        with zipfile.ZipFile(temporary, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
            for path in sorted(item for item in package_directory.rglob("*") if item.is_file()):
                relative = path.relative_to(package_directory).as_posix()
                archive.write(path, f"{package_directory.name}/{relative}")
        os.replace(temporary, archive_path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def generate(arguments: argparse.Namespace) -> dict[str, Any]:
    try:
        sn = validate_body_sn(arguments.sn)
    except ValueError as exc:
        raise GenerationError(str(exc)) from exc
    ssid, normalized_ssid = _validate_ssid(arguments.ssid)
    model = _validate_model(arguments.model)
    bssid = _validate_bssid(arguments.bssid)
    sn_source_reference = _validate_evidence(arguments.sn_source_reference, "SN source reference")
    new_board_evidence = _validate_evidence(arguments.new_board_evidence, "new-board evidence")
    new_board_evidence_raw_sha256 = _sha256_bytes(new_board_evidence.encode("utf-8"))
    new_board_evidence_sha256 = _sha256_bytes(
        _normalize_evidence_for_history(new_board_evidence).encode("utf-8")
    )

    missing_confirmations: list[str] = []
    if not arguments.ownership_confirmed:
        missing_confirmations.append("--ownership-confirmed")
    if not arguments.trusted_source_confirmed:
        missing_confirmations.append("--trusted-source-confirmed")
    if not arguments.new_physical_board_confirmed:
        missing_confirmations.append("--new-physical-board-confirmed")
    if missing_confirmations:
        raise GenerationError("generation refused; missing explicit confirmation(s): " + ", ".join(missing_confirmations))

    if arguments.previous_incident_id is not None and INCIDENT_RE.fullmatch(arguments.previous_incident_id) is None:
        raise GenerationError("previous incident ID has an invalid format")

    output_root = Path(arguments.output).expanduser().resolve()
    try:
        output_root.relative_to(PROJECT_DIRECTORY)
    except ValueError:
        pass
    else:
        raise GenerationError(
            f"output may not be the source/template tree or any of its descendants: {PROJECT_DIRECTORY}"
        )
    state_directory = _local_state_directory()
    history_path = state_directory / "events.jsonl"
    lock_path = state_directory / "history.lock"
    device_key = _device_key(sn, normalized_ssid)

    created_paths: list[Path] = []
    staging_directory: Path | None = None
    with _ExclusiveHistoryLock(lock_path):
        history = _read_history(history_path)
        priors = _matching_prior_events(sn, normalized_ssid, history)
        if priors:
            latest_id = str(priors[-1]["incidentId"])
            if arguments.previous_incident_id != latest_id:
                existing_path = priors[-1].get("packagePath")
                extra = f" Existing package: {existing_path}." if existing_path else ""
                raise GenerationError(
                    "a prior event exists for this SN or service SSID. Do not create another package for the same "
                    f"board. Only after a genuinely new physical board replacement, repeat with "
                    f"--previous-incident-id {latest_id}.{extra}"
                )
            if not arguments.later_physical_board_event_confirmed:
                raise GenerationError(
                    "history exists; --later-physical-board-event-confirmed is required in addition to the normal new-board confirmation"
                )
            for record in priors:
                hash_version = record.get("newBoardEvidenceHashVersion")
                if hash_version == EVIDENCE_HASH_VERSION:
                    prior_hash = record.get("newBoardEvidenceSha256")
                elif hash_version is None:
                    if record.get("newBoardEvidenceSha256") == new_board_evidence_raw_sha256:
                        raise GenerationError(
                            "new-board evidence is identical to a prior event; a later physical replacement needs fresh evidence"
                        )
                    raise GenerationError(
                        "prior event uses an unversioned evidence hash, so whitespace/case variants cannot be safely distinguished; "
                        "stop for manual history migration and evidence review"
                    )
                else:
                    raise GenerationError(
                        f"prior event uses unsupported evidence hash version {hash_version!r}; stop for manual review"
                    )
                if prior_hash == new_board_evidence_sha256:
                    raise GenerationError(
                        "new-board evidence is identical to a prior event; a later physical replacement needs fresh evidence"
                    )
        elif arguments.previous_incident_id is not None:
            raise GenerationError("--previous-incident-id was supplied, but no prior event exists for this identity")
        elif arguments.later_physical_board_event_confirmed:
            raise GenerationError(
                "--later-physical-board-event-confirmed was supplied, but no prior event exists for this identity"
            )

        output_root.mkdir(parents=True, exist_ok=True)
        incident_id = str(uuid.uuid4())
        generated_utc = _utc_now()
        package_name = f"midea-sn-{sn[-4:]}-{normalized_ssid[-4:]}-{incident_id[:8]}"
        final_directory = output_root / package_name
        archive_path = output_root / f"{package_name}.zip"
        sha_path = output_root / f"{package_name}.zip.sha256"
        for candidate in (final_directory, archive_path, sha_path):
            if candidate.exists():
                raise GenerationError(f"output already exists and will not be overwritten: {candidate}")

        # Reserve the identity/incident in append-only history before any
        # unlocked package becomes visible.  If the process crashes later,
        # this conservative reservation remains and prevents a second package
        # with another incident lock from being emitted for the same board.
        reservation_event = {
            "schemaVersion": SCHEMA_VERSION,
            "incidentId": incident_id,
            "previousIncidentId": arguments.previous_incident_id,
            "targetSn": sn,
            "expectedServiceSsid": ssid,
            "normalizedServiceSsid": normalized_ssid,
            "expectedBssid": bssid,
            "model": model,
            "snSource": arguments.sn_source,
            "newBoardEvidenceSha256": new_board_evidence_sha256,
            "newBoardEvidenceHashVersion": EVIDENCE_HASH_VERSION,
            "laterPhysicalBoardEventConfirmed": bool(priors),
            "deviceKey": device_key,
            "generatedUtc": generated_utc,
            "status": "PACKAGE_GENERATION_RESERVED",
            "intendedPackagePath": str(final_directory),
            "intendedArchivePath": str(archive_path),
        }
        _append_history(history_path, reservation_event)

        staging_directory = output_root / f".{package_name}.building-{uuid.uuid4().hex}"
        staging_directory.mkdir(parents=False, exist_ok=False)
        created_paths.append(staging_directory)
        try:
            replacements = _template_replacements(
                sn=sn,
                ssid=ssid,
                normalized_ssid=normalized_ssid,
                bssid=bssid,
                model=model,
                incident_id=incident_id,
                device_key=device_key,
                generated_utc=generated_utc,
                sn_source=arguments.sn_source,
            )
            _render_template_tree(staging_directory, replacements)
            _static_render_checks(staging_directory, sn, ssid, replacements["WRITE_CONFIRMATION"])
            file_hashes = _relative_hashes(staging_directory)
            vectors = target_vectors(sn)
            manifest: dict[str, Any] = {
                "schemaVersion": SCHEMA_VERSION,
                "generator": {
                    "name": "midea-sn-board-restore-standalone/generator.py",
                    "version": GENERATOR_VERSION,
                    "offlineOnly": True,
                    "generatedUtc": generated_utc,
                },
                "repairEvent": {
                    "incidentId": incident_id,
                    "previousIncidentId": arguments.previous_incident_id,
                    "deviceKey": device_key,
                    "ownerOrAuthorizedConfirmed": True,
                    "newPhysicalBoardConfirmed": True,
                    "laterPhysicalBoardEventConfirmed": bool(priors),
                    "newBoardEvidence": new_board_evidence,
                    "newBoardEvidenceSha256": new_board_evidence_sha256,
                    "newBoardEvidenceHashVersion": EVIDENCE_HASH_VERSION,
                },
                "target": {
                    "bodySn": sn,
                    "encodedHex": vectors["encoded"],
                    "encodedBytes": list(encode_sn(sn)),
                    "model": model,
                    "snSource": arguments.sn_source,
                    "trustedSourceConfirmed": True,
                    "snSourceReference": sn_source_reference,
                },
                "network": {
                    "expectedServiceSsid": ssid,
                    "normalizedServiceSsid": normalized_ssid,
                    "expectedBssid": bssid,
                    "targetHost": "192.168.1.1",
                    "targetPort": 6444,
                },
                "protocol": {
                    "applianceType": "0xAC",
                    "queryOpcode": "0x40",
                    "writeOpcode": "0x41",
                    "targetVectors": vectors,
                },
                "safety": {
                    "diagnosticZeroBytesPhrase": "ZERO-BYTES-IS-NOT-PROOF",
                    "newBoardAndOriginalSnPhrase": "NEW-BOARD-AND-ORIGINAL-SN-CONFIRMED",
                    "writeConfirmation": replacements["WRITE_CONFIRMATION"],
                    "writeRequestLimit": 1,
                    "writeRetryAllowed": False,
                    "locksAreBestEffortNotHardwareDrm": True,
                },
                "files": file_hashes,
            }
            _write_json(staging_directory / "TARGET.json", manifest)
            os.replace(staging_directory, final_directory)
            created_paths.remove(staging_directory)
            staging_directory = None
            created_paths.append(final_directory)

            _zip_package(final_directory, archive_path)
            created_paths.append(archive_path)
            archive_sha = _sha256_file(archive_path)
            sha_path.write_text(f"{archive_sha}  {archive_path.name}\n", encoding="ascii")
            created_paths.append(sha_path)

            event = {
                "schemaVersion": SCHEMA_VERSION,
                "incidentId": incident_id,
                "previousIncidentId": arguments.previous_incident_id,
                "targetSn": sn,
                "expectedServiceSsid": ssid,
                "normalizedServiceSsid": normalized_ssid,
                "expectedBssid": bssid,
                "model": model,
                "snSource": arguments.sn_source,
                "newBoardEvidenceSha256": new_board_evidence_sha256,
                "newBoardEvidenceHashVersion": EVIDENCE_HASH_VERSION,
                "laterPhysicalBoardEventConfirmed": bool(priors),
                "deviceKey": device_key,
                "generatedUtc": generated_utc,
                "status": "PACKAGE_GENERATED_NOT_EXECUTED",
                "packagePath": str(final_directory),
                "archivePath": str(archive_path),
                "archiveSha256": archive_sha,
            }
            _append_history(history_path, event)
        except Exception:
            if staging_directory is not None and staging_directory.exists():
                shutil.rmtree(staging_directory)
            for path in reversed(created_paths):
                if path.is_dir():
                    shutil.rmtree(path)
                else:
                    try:
                        path.unlink()
                    except FileNotFoundError:
                        pass
            raise

    return {
        "result": "PACKAGE_GENERATED_NOT_EXECUTED",
        "incidentId": incident_id,
        "packageDirectory": str(final_directory),
        "archive": str(archive_path),
        "archiveSha256": archive_sha,
        "sha256File": str(sha_path),
        "history": str(history_path),
        "writeConfirmation": replacements["WRITE_CONFIRMATION"],
    }


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Offline generator for one immutable, write-once Midea replacement-board body-SN restore package. "
            "It does not connect to or execute against an appliance."
        )
    )
    parser.add_argument("--sn", required=True, help="exact 22-ASCII-digit original body SN; 32-digit App values fail")
    parser.add_argument("--ssid", required=True, help="exact live service SSID: midea_test_<12 hex>")
    parser.add_argument(
        "--model",
        required=True,
        choices=COMPATIBLE_MODELS,
        help="exact model; this release is restricted to the verified compatibility allowlist",
    )
    parser.add_argument("--bssid", help="optional exact live service BSSID")
    parser.add_argument("--sn-source", required=True, choices=SOURCE_CHOICES)
    parser.add_argument("--sn-source-reference", required=True, help="one-line evidence reference, not another SN")
    parser.add_argument("--new-board-evidence", required=True, help="one-line reference to evidence of the new board")
    parser.add_argument("--ownership-confirmed", action="store_true")
    parser.add_argument("--trusted-source-confirmed", action="store_true")
    parser.add_argument("--new-physical-board-confirmed", action="store_true")
    parser.add_argument(
        "--later-physical-board-event-confirmed",
        action="store_true",
        help="additional attestation required only when SN or service-SSID history exists; it is not proof and remains subject to evidence review",
    )
    parser.add_argument(
        "--previous-incident-id",
        help="required only for a genuinely later physical-board replacement when either SN or service SSID has history",
    )
    parser.add_argument("--output", required=True, help="parent directory for the immutable folder, ZIP and SHA256")
    return parser


def main() -> int:
    parser = _build_parser()
    arguments = parser.parse_args()
    try:
        result = generate(arguments)
    except (GenerationError, OSError, ValueError) as exc:
        print(f"GENERATION_REFUSED: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
