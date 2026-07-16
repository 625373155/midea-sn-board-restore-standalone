from __future__ import annotations

"""Fail-closed validator for a generated Midea body-SN restore package."""

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import unicodedata
import zipfile
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Any

from .protocol import encode_sn, target_vectors, validate_body_sn


SERVICE_SSID_RE = re.compile(r"midea_test_[0-9A-Fa-f]{12}\Z", re.ASCII)
MODEL_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9@._+()/\-]{0,63}\Z", re.ASCII)
COMPATIBLE_MODELS = ("KFR-26G/WXAA2@",)
INCIDENT_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z",
    re.ASCII,
)
PREVIOUS_INCIDENT_RE = re.compile(
    r"(?:[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}|legacy-[a-z0-9-]{4,80})\Z",
    re.ASCII,
)
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
TOKEN_RE = re.compile(r"@@[A-Z][A-Z0-9_]*@@", re.ASCII)
TEMPLATE_TOKEN_RE = re.compile(r"@@([A-Z][A-Z0-9_]*)@@", re.ASCII)
TEMPLATE_DIRECTORY = Path(__file__).resolve().parent / "templates"
EXPECTED_GENERATOR_NAME = "midea-sn-board-restore-standalone/generator.py"
EXPECTED_GENERATOR_VERSION = "1.3.0"
EXPECTED_EVIDENCE_HASH_VERSION = "nfkc-casefold-whitespace-v1"
EXPECTED_LAUNCHERS = {
    "00_self_test.cmd": "SelfTest",
    "01_query_only.cmd": "Query",
    "02_restore_once_and_verify.cmd": "Write",
    "03_raw_read_only_diagnostic.cmd": "Diagnostic",
    "04_post_write_read_only_check.cmd": "PostWriteCheck",
}


class ValidationError(RuntimeError):
    """A package integrity or safety invariant failed."""


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _device_key(sn: str, normalized_ssid: str) -> str:
    return hashlib.sha256(f"{sn}|{normalized_ssid}".encode("ascii")).hexdigest()


def _normalize_ssid(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9]", "", value).lower()


def _load_manifest(package_directory: Path) -> dict[str, Any]:
    path = package_directory / "TARGET.json"
    if not path.is_file():
        raise ValidationError("TARGET.json is missing")
    try:
        value = json.loads(path.read_text(encoding="utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValidationError(f"TARGET.json is not valid UTF-8 JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise ValidationError("TARGET.json must contain one JSON object")
    return value


def _require_dict(container: dict[str, Any], key: str) -> dict[str, Any]:
    value = container.get(key)
    if not isinstance(value, dict):
        raise ValidationError(f"manifest field {key!r} must be an object")
    return value


def _validate_manifest(manifest: dict[str, Any]) -> dict[str, Any]:
    if manifest.get("schemaVersion") != 1:
        raise ValidationError("unsupported TARGET.json schemaVersion")
    generator = _require_dict(manifest, "generator")
    repair = _require_dict(manifest, "repairEvent")
    target = _require_dict(manifest, "target")
    network = _require_dict(manifest, "network")
    protocol = _require_dict(manifest, "protocol")
    safety = _require_dict(manifest, "safety")

    if generator.get("name") != EXPECTED_GENERATOR_NAME or generator.get("version") != EXPECTED_GENERATOR_VERSION:
        raise ValidationError("manifest generator name/version does not match this validator release")
    if generator.get("offlineOnly") is not True:
        raise ValidationError("manifest does not declare an offline-only generator")
    generated_utc = generator.get("generatedUtc")
    if not isinstance(generated_utc, str):
        raise ValidationError("manifest generatedUtc is missing")
    try:
        datetime.strptime(generated_utc, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise ValidationError("manifest generatedUtc is not canonical UTC-to-seconds text") from exc
    sn = target.get("bodySn")
    try:
        validate_body_sn(sn)
    except ValueError as exc:
        raise ValidationError(str(exc)) from exc

    ssid = network.get("expectedServiceSsid")
    if not isinstance(ssid, str) or SERVICE_SSID_RE.fullmatch(ssid) is None:
        raise ValidationError("manifest service SSID does not match midea_test_<12 hex>")
    normalized_ssid = network.get("normalizedServiceSsid")
    if normalized_ssid != _normalize_ssid(ssid):
        raise ValidationError("manifest normalized service SSID is inconsistent")

    bssid = network.get("expectedBssid")
    if bssid is not None and re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", str(bssid), re.ASCII) is None:
        raise ValidationError("manifest BSSID is not null or canonical lowercase hexadecimal")
    if bssid in {"00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"}:
        raise ValidationError("manifest BSSID cannot be all-zero or broadcast")
    if bssid is not None and int(str(bssid)[0:2], 16) & 1:
        raise ValidationError("manifest BSSID cannot be multicast")

    incident_id = repair.get("incidentId")
    if not isinstance(incident_id, str) or INCIDENT_RE.fullmatch(incident_id) is None:
        raise ValidationError("manifest incident ID must be a canonical lowercase UUIDv4")
    expected_device_key = _device_key(sn, normalized_ssid)
    if repair.get("deviceKey") != expected_device_key:
        raise ValidationError("manifest device key does not match SN + normalized service SSID")
    if repair.get("ownerOrAuthorizedConfirmed") is not True:
        raise ValidationError("owner/authorized-use confirmation is missing")
    if repair.get("newPhysicalBoardConfirmed") is not True:
        raise ValidationError("new-physical-board confirmation is missing")
    previous_incident_id = repair.get("previousIncidentId")
    if previous_incident_id is not None and (
        not isinstance(previous_incident_id, str)
        or PREVIOUS_INCIDENT_RE.fullmatch(previous_incident_id) is None
    ):
        raise ValidationError("previous incident ID is not a UUIDv4 or approved legacy identifier")
    expected_later_confirmation = previous_incident_id is not None
    if repair.get("laterPhysicalBoardEventConfirmed") is not expected_later_confirmation:
        raise ValidationError(
            "later-physical-board-event confirmation is inconsistent with previousIncidentId"
        )
    new_board_evidence = repair.get("newBoardEvidence")
    if (
        not isinstance(new_board_evidence, str)
        or not 3 <= len(new_board_evidence) <= 240
        or new_board_evidence != new_board_evidence.strip()
        or not new_board_evidence.isprintable()
        or "\r" in new_board_evidence
        or "\n" in new_board_evidence
    ):
        raise ValidationError("new-board evidence reference is missing")
    if repair.get("newBoardEvidenceHashVersion") != EXPECTED_EVIDENCE_HASH_VERSION:
        raise ValidationError("new-board evidence hash normalization version is missing or unsupported")
    evidence_normalized = re.sub(
        r"\s+", " ", unicodedata.normalize("NFKC", new_board_evidence).casefold()
    ).strip()
    expected_evidence_hash = hashlib.sha256(evidence_normalized.encode("utf-8")).hexdigest()
    if repair.get("newBoardEvidenceSha256") != expected_evidence_hash:
        raise ValidationError("new-board evidence normalized hash is inconsistent")
    if target.get("trustedSourceConfirmed") is not True:
        raise ValidationError("trusted-SN-source confirmation is missing")
    if target.get("snSource") not in {"customer-service", "original-label", "old-app", "old-board"}:
        raise ValidationError("unrecognized trusted SN source")
    sn_source_reference = target.get("snSourceReference")
    if (
        not isinstance(sn_source_reference, str)
        or not 3 <= len(sn_source_reference) <= 240
        or sn_source_reference != sn_source_reference.strip()
        or not sn_source_reference.isprintable()
        or "\r" in sn_source_reference
        or "\n" in sn_source_reference
    ):
        raise ValidationError("SN source evidence reference is missing")
    model = target.get("model")
    if not isinstance(model, str) or MODEL_RE.fullmatch(model) is None:
        raise ValidationError("manifest model is not 1-64 safe ASCII characters")
    if model not in COMPATIBLE_MODELS:
        raise ValidationError("manifest model is outside the verified compatibility allowlist")
    previous_incident_id = repair.get("previousIncidentId")
    if previous_incident_id is not None and (
        not isinstance(previous_incident_id, str)
        or re.fullmatch(
            r"(?:[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}|legacy-[a-z0-9-]{4,80})",
            previous_incident_id,
            re.ASCII,
        )
        is None
    ):
        raise ValidationError("previous incident ID is neither null, a UUIDv4, nor an immutable legacy event ID")

    vectors = target_vectors(sn)
    if target.get("encodedHex") != vectors["encoded"]:
        raise ValidationError("manifest encoded target SN does not match the reference encoder")
    if target.get("encodedBytes") != list(encode_sn(sn)):
        raise ValidationError("manifest encoded target byte list does not match the reference encoder")
    if protocol.get("targetVectors") != vectors:
        raise ValidationError("manifest target protocol vectors do not match the reference implementation")
    if protocol.get("applianceType") != "0xAC":
        raise ValidationError("manifest appliance type is not 0xAC")
    if protocol.get("queryOpcode") != "0x40" or protocol.get("writeOpcode") != "0x41":
        raise ValidationError("manifest query/write opcodes are not 0x40/0x41")
    if network.get("targetHost") != "192.168.1.1" or network.get("targetPort") != 6444:
        raise ValidationError("manifest target endpoint is not fixed to 192.168.1.1:6444")

    expected_write_confirmation = f"WRITE-{sn[-4:]}-{normalized_ssid[-4:].upper()}-{incident_id[:8].upper()}-ONCE"
    if safety.get("writeConfirmation") != expected_write_confirmation:
        raise ValidationError("write confirmation phrase is not bound to SN, SSID and incident")
    if safety.get("diagnosticZeroBytesPhrase") != "ZERO-BYTES-IS-NOT-PROOF":
        raise ValidationError("zero-byte diagnostic acknowledgment is missing or misleading")
    if safety.get("newBoardAndOriginalSnPhrase") != "NEW-BOARD-AND-ORIGINAL-SN-CONFIRMED":
        raise ValidationError("new-board/original-SN acknowledgment is missing")
    if safety.get("writeRequestLimit") != 1 or safety.get("writeRetryAllowed") is not False:
        raise ValidationError("manifest does not enforce a single non-retryable write request")

    return {
        "sn": sn,
        "ssid": ssid,
        "normalizedSsid": normalized_ssid,
        "bssid": bssid,
        "incidentId": incident_id,
        "deviceKey": expected_device_key,
        "writeConfirmation": expected_write_confirmation,
        "vectors": vectors,
        "model": model,
        "snSource": target["snSource"],
        "generatedUtc": generated_utc,
    }


def _hex_to_ps_array(value: str) -> str:
    return ", ".join(f"0x{item}" for item in value.split())


def _template_replacements(identity: dict[str, Any]) -> dict[str, str]:
    vectors = identity["vectors"]
    sn = identity["sn"]
    normalized_ssid = identity["normalizedSsid"]
    incident_id = identity["incidentId"]
    return {
        "TARGET_SN": sn,
        "TARGET_SN_LAST4": sn[-4:],
        "TARGET_SN_MASKED": f"{sn[:6]}{'*' * 12}{sn[-4:]}",
        "TARGET_ENCODED_HEX": vectors["encoded"],
        "TARGET_ENCODED_ARRAY": _hex_to_ps_array(vectors["encoded"]),
        "EXPECTED_SSID": identity["ssid"],
        "EXPECTED_SSID_NORMALIZED": normalized_ssid,
        "EXPECTED_SSID_LAST4": normalized_ssid[-4:],
        "EXPECTED_BSSID": identity["bssid"] or "",
        "EXPECTED_BSSID_REQUIRED": "$true" if identity["bssid"] else "$false",
        "MODEL": identity["model"],
        "INCIDENT_ID": incident_id,
        "INCIDENT_ID_SHORT": incident_id[:8],
        "DEVICE_KEY": identity["deviceKey"],
        "WRITE_CONFIRMATION": identity["writeConfirmation"],
        "GENERATED_UTC": identity["generatedUtc"],
        "SN_SOURCE": identity["snSource"],
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


def _validate_exact_template_tree(package_directory: Path, identity: dict[str, Any]) -> None:
    """Require every generated runtime file to be an exact rendering of this release.

    The structural checks below are intentionally redundant and readable, while
    this byte-for-byte provenance gate makes any extra command, moved safety
    check, alternate endpoint, or opcode spelling fail closed even if a manifest
    hash was also edited.
    """

    if not TEMPLATE_DIRECTORY.is_dir():
        raise ValidationError(f"validator template directory is missing: {TEMPLATE_DIRECTORY}")
    template_paths = sorted(path for path in TEMPLATE_DIRECTORY.rglob("*") if path.is_file())
    if not template_paths:
        raise ValidationError("validator template directory is empty")
    replacements = _template_replacements(identity)
    expected_names: set[str] = set()
    for template_path in template_paths:
        if template_path.is_symlink():
            raise ValidationError(f"validator refuses a symlinked template resource: {template_path}")
        relative = template_path.relative_to(TEMPLATE_DIRECTORY)
        rendered_relative = (
            relative.with_name(relative.name[:-5]) if relative.name.endswith(".tmpl") else relative
        )
        rendered_name = rendered_relative.as_posix()
        expected_names.add(rendered_name)
        target_path = package_directory / rendered_relative
        if not target_path.is_file() or target_path.is_symlink():
            raise ValidationError(f"exact rendered runtime file is missing or unsafe: {rendered_name}")
        if template_path.name.endswith(".tmpl"):
            try:
                rendered = template_path.read_text(encoding="utf-8-sig")
            except UnicodeDecodeError as exc:
                raise ValidationError(f"validator template is not valid UTF-8: {template_path}") from exc
            for token in sorted(set(TEMPLATE_TOKEN_RE.findall(rendered))):
                if token not in replacements:
                    raise ValidationError(f"validator template contains unsupported token @@{token}@@")
                rendered = rendered.replace(f"@@{token}@@", replacements[token])
            if TEMPLATE_TOKEN_RE.search(rendered):
                raise ValidationError(f"validator template retained an unresolved token: {template_path.name}")
            expected_bytes = rendered.encode("utf-8-sig" if target_path.suffix.lower() == ".ps1" else "utf-8")
        else:
            expected_bytes = template_path.read_bytes()
        if target_path.read_bytes() != expected_bytes:
            raise ValidationError(
                f"runtime file is not the exact audited rendering from this source release: {rendered_name}"
            )

    actual_names = {
        relative
        for path in package_directory.rglob("*")
        if path.is_file()
        for relative in (path.relative_to(package_directory).as_posix(),)
        if relative != "TARGET.json"
    }
    if actual_names != expected_names:
        raise ValidationError(
            f"runtime/template file set mismatch; expected={sorted(expected_names)}, actual={sorted(actual_names)}"
        )


def _validate_file_hashes(package_directory: Path, manifest: dict[str, Any]) -> list[str]:
    declared = manifest.get("files")
    if not isinstance(declared, dict) or not declared:
        raise ValidationError("manifest files hash table is missing or empty")
    normalized_declared: dict[str, str] = {}
    for relative, expected_hash in declared.items():
        if not isinstance(relative, str) or not relative or "\\" in relative:
            raise ValidationError("manifest file names must be non-empty POSIX relative paths")
        pure = PurePosixPath(relative)
        if pure.is_absolute() or ".." in pure.parts or relative == "TARGET.json":
            raise ValidationError(f"unsafe or circular manifest file entry: {relative!r}")
        if not isinstance(expected_hash, str) or SHA256_RE.fullmatch(expected_hash) is None:
            raise ValidationError(f"invalid SHA-256 value for {relative!r}")
        normalized_declared[relative] = expected_hash

    actual_paths: dict[str, Path] = {}
    for path in sorted(package_directory.rglob("*")):
        if path.is_symlink():
            raise ValidationError(f"package may not contain symlinks: {path}")
        if path.is_file():
            relative = path.relative_to(package_directory).as_posix()
            if relative != "TARGET.json":
                actual_paths[relative] = path
    if set(normalized_declared) != set(actual_paths):
        missing = sorted(set(normalized_declared) - set(actual_paths))
        untracked = sorted(set(actual_paths) - set(normalized_declared))
        raise ValidationError(f"manifest/file set mismatch; missing={missing}, untracked={untracked}")
    for relative, path in actual_paths.items():
        actual_hash = _sha256_file(path)
        if actual_hash != normalized_declared[relative]:
            raise ValidationError(f"SHA-256 mismatch for {relative}")
    return sorted(["TARGET.json", *actual_paths])


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ValidationError(f"expected UTF-8 text file is not valid UTF-8: {path.name}") from exc


def _function_body(text: str, name: str) -> str:
    match = re.search(
        rf"(?is)function\s+{re.escape(name)}\s*\{{(.*?)(?=\r?\nfunction\s+|\Z)", text
    )
    if match is None:
        raise ValidationError(f"PowerShell is missing audited function {name}")
    return match.group(1)


def _validate_launchers(package_directory: Path) -> None:
    cmd_paths = {path.name: path for path in package_directory.glob("*.cmd")}
    if set(cmd_paths) != set(EXPECTED_LAUNCHERS):
        raise ValidationError(
            f"launcher set differs from the five audited launchers: {sorted(cmd_paths)}"
        )
    for name, expected_mode in EXPECTED_LAUNCHERS.items():
        text = _read_text(cmd_paths[name])
        if TOKEN_RE.search(text):
            raise ValidationError(f"launcher contains unresolved template token: {name}")
        invocations = re.findall(r"(?i)-Mode\s+([A-Za-z]+)", text)
        if invocations != [expected_mode]:
            raise ValidationError(
                f"launcher {name} must make exactly one -Mode {expected_mode} invocation; got {invocations}"
            )
        if expected_mode != "Write" and re.search(r"(?i)\bWrite\b", " ".join(invocations)):
            raise ValidationError(f"read-only launcher invokes Write mode: {name}")


def _validate_powershell(package_directory: Path, identity: dict[str, Any]) -> Path:
    _validate_exact_template_tree(package_directory, identity)
    scripts = list(package_directory.glob("*.ps1"))
    if [path.name for path in scripts] != ["midea_sn_restore.ps1"]:
        raise ValidationError("package must contain exactly midea_sn_restore.ps1")
    script = scripts[0]
    text = _read_text(script)
    if TOKEN_RE.search(text):
        raise ValidationError("PowerShell contains an unresolved template token")

    top_param = re.match(r"(?is)^\ufeff?\s*param\s*\((.*?)\)\s*", text)
    if top_param and re.search(r"(?i)\$TargetSn\b", top_param.group(1)):
        raise ValidationError("PowerShell exposes a runtime TargetSn parameter")
    target_assignments = re.findall(r"(?im)^\s*\$TargetSn\s*=\s*'([0-9]+)'\s*$", text)
    if target_assignments != [identity["sn"]]:
        raise ValidationError(f"PowerShell target SN assignment is not exactly the manifest target: {target_assignments}")

    required_literals = {
        identity["ssid"]: "service SSID",
        identity["incidentId"]: "incident ID",
        identity["deviceKey"]: "device key",
        identity["writeConfirmation"]: "write confirmation phrase",
        identity["vectors"]["encoded"]: "encoded target vector",
        "NEW-BOARD-AND-ORIGINAL-SN-CONFIRMED": "new-board confirmation phrase",
        "ZERO-BYTES-IS-NOT-PROOF": "zero-byte uncertainty phrase",
        "192.168.1.1": "fixed target host",
        "6444": "fixed target port",
        "WRITE-ATTEMPTED-DO-NOT-RERUN": "package-side persistent marker",
        "READ-ONLY-ALREADY-CORRECT-DO-NOT-WRITE": "already-correct permanent stop marker",
        "READ-MISMATCH-DO-NOT-WRITE": "mismatch permanent stop marker",
        "READ-INVALID-DO-NOT-WRITE": "invalid-encoding permanent stop marker",
        "TARGET.json": "runtime package-integrity manifest",
    }
    if identity["bssid"] is not None:
        required_literals[identity["bssid"]] = "BSSID"
    for literal, label in required_literals.items():
        if literal not in text:
            raise ValidationError(f"PowerShell is missing its fixed {label}")

    if re.search(r"(?im)^\s*\$KnownPriorWriteAttempt\s*=\s*\$false\s*$", text) is None:
        raise ValidationError("fresh repair package is not explicitly marked as having no prior write in this event")
    if re.search(r"(?im)^\s*if\s*\(\$ssid\s*-cne\s*\$ExpectedSsidDisplay\)\s*\{", text) is None:
        raise ValidationError("PowerShell does not require exact case-preserved service SSID equality")
    if re.search(r"(?i)Normalize-Ssid\s+\$ssid", text):
        raise ValidationError("PowerShell must not use relaxed SSID normalization for live Wi-Fi binding")
    host_assignments = re.findall(r"(?im)^\s*\$TargetHost\s*=\s*'([^']+)'\s*$", text)
    port_assignments = re.findall(r"(?im)^\s*\$TargetPort\s*=\s*([0-9]+)\s*$", text)
    if host_assignments != ["192.168.1.1"] or port_assignments != ["6444"]:
        raise ValidationError("PowerShell target host/port are not unique fixed assignments")
    expected_bssid_literal = identity["bssid"] or ""
    bssid_assignments = re.findall(r"(?im)^\s*\$ExpectedBssid\s*=\s*'([^']*)'\s*$", text)
    if bssid_assignments != [expected_bssid_literal]:
        raise ValidationError("PowerShell BSSID assignment does not match the manifest")
    expected_bssid_required = "$true" if identity["bssid"] is not None else "$false"
    bssid_required_assignments = re.findall(
        r"(?im)^\s*\$ExpectedBssidRequired\s*=\s*(\$true|\$false)\s*$", text
    )
    if bssid_required_assignments != [expected_bssid_required]:
        raise ValidationError("PowerShell BSSID-required gate does not match whether manifest BSSID is present")
    if re.search(r"\[System\.IO\.FileMode\]::CreateNew", text, re.IGNORECASE) is None:
        raise ValidationError("PowerShell lacks an atomic CreateNew write reservation")
    if re.search(r"\.Flush\(\$true\)", text, re.IGNORECASE) is None:
        raise ValidationError("PowerShell does not durably flush its write reservation")
    if len(re.findall(r"(?im)^\s*Send-SingleAuthorizedWrite\b", text)) != 1:
        raise ValidationError("PowerShell must invoke Send-SingleAuthorizedWrite exactly once")
    single_write_body = _function_body(text, "Send-SingleAuthorizedWrite")
    if len(re.findall(r"(?im)^\s*Send-Packet\b", single_write_body)) != 1:
        raise ValidationError("authorized-write function must contain exactly one packet-send command")
    if len(re.findall(r"(?im)^\s*\[byte\[\]\]\$inner\s*=\s*New-TargetWriteInnerPacket\s+-Counter\s+1\s*$", single_write_body)) != 1:
        raise ValidationError("authorized-write function must construct exactly one fixed-counter target packet")
    if re.search(r"(?i)for(each)?\s*\(|while\s*\(|do\s*\{", single_write_body):
        raise ValidationError("authorized-write function may not contain a retry loop")
    if len(re.findall(r"(?im)^\s*\$body\[11\]\s*=\s*0x41\s*$", text)) != 1:
        raise ValidationError("PowerShell must contain exactly one write-opcode construction assignment")
    if len(re.findall(r"(?im)New-TargetWriteInnerPacket\s+-Counter\s+1\b", text)) != 1:
        raise ValidationError("target write-packet constructor must be called exactly once")
    if re.search(r"(?i)New-InnerSnPacket|\-IsWrite\b", text):
        raise ValidationError("read/write-generic packet constructor is forbidden")

    read_builder_body = _function_body(text, "New-ReadOnlySnPacket")
    if re.search(r"(?i)0x41|TargetEncodedSn|New-TargetWriteInnerPacket", read_builder_body):
        raise ValidationError("read-only packet builder can reach write-specific data or opcode")
    read_self_test_body = _function_body(text, "Assert-ReadOnlyProtocolSelfTest")
    if re.search(
        r"(?i)0x41|New-TargetWriteInnerPacket|Assert-TargetWritePacket|Send-Packet|\.Write\(",
        read_self_test_body,
    ):
        raise ValidationError("read-only PowerShell SelfTest constructs or sends a write operation")

    decoder_body = _function_body(text, "ConvertFrom-EncodedBodySn")
    if "Encoded body SN must contain exactly 22 bytes" not in decoder_body:
        raise ValidationError("strict readback decoder does not enforce the 22-byte identity length")
    strict_parser_body = _function_body(text, "Get-StrictSnFramesFromRaw")
    if len(re.findall(r"(?im)^\s*\[string\]\$decodedSn\s*=\s*ConvertFrom-EncodedBodySn\b", strict_parser_body)) != 1:
        raise ValidationError("strict frame parser must decode the body SN exactly once")
    if "INVALID_SN_ENCODING" not in strict_parser_body or "DecodedSn = $decodedSn" not in strict_parser_body:
        raise ValidationError("strict frame parser lacks invalid-encoding separation or decoded-SN evidence")
    if re.search(r"(?i)TargetEncodedSn", strict_parser_body):
        raise ValidationError("strict frame parser compares encoded bytes directly instead of validating decoded identity")
    if re.search(r"(?i)\$matchesTarget\s*=\s*\(\$decodedSn\s+-ceq\s+\$TargetSn\)", strict_parser_body) is None:
        raise ValidationError("strict frame parser does not compare the decoded 22-digit SN exactly")

    send_packet_body = _function_body(text, "Send-Packet")
    if len(re.findall(r"(?im)^\s*\$Stream\.Write\(", send_packet_body)) != 1:
        raise ValidationError("network packet sender must contain exactly one NetworkStream.Write call")
    if len(re.findall(r"(?im)^\s*\$WriteRequestSent\.Value\s*=\s*\$true\s*$", send_packet_body)) != 1:
        raise ValidationError("network sender must mark the write call as begun exactly once")
    if re.search(
        r"(?is)\$WriteRequestSent\.Value\s*=\s*\$true\s*\}\s*\$Stream\.Write\(",
        send_packet_body,
    ) is None:
        raise ValidationError("write-begun flag is not immediately adjacent to NetworkStream.Write")
    if re.search(r"(?im)^\s*\$WriteRequestSent\.Value\s*=", single_write_body):
        raise ValidationError("authorized-write dispatcher marks send too early, before entering the network sender")
    if len(re.findall(r"(?i)\$Stream\.Write\s*\(", text)) != 1:
        raise ValidationError("PowerShell contains an extra or disguised NetworkStream.Write call")
    text_without_sender = text.replace(send_packet_body, "")
    if re.search(r"(?im)^\s*\$Stream\.Write\(", text_without_sender):
        raise ValidationError("a NetworkStream.Write call exists outside the audited packet sender")
    if len(re.findall(r"(?im)^\s*Send-Packet\b", text)) != 4:
        raise ValidationError("unexpected number of packet-send call sites in the audited runtime")
    write_send_calls = re.findall(
        r"(?im)^\s*Send-Packet\s+-Stream\s+\$Stream\s+-Packet\s+\$packet\s+-WriteRequestSent\s+\$WriteRequestSent\s*$",
        text,
    )
    read_send_calls = re.findall(
        r"(?im)^\s*Send-Packet\s+-Stream\s+\$stream\s+-Packet\s+\$(diagnosticPacket|packet|readPacket)\s*$",
        text,
    )
    if len(write_send_calls) != 1 or read_send_calls != ["diagnosticPacket", "packet", "readPacket"]:
        raise ValidationError(
            f"packet-send call sites differ from the audited write/read sequence: write={len(write_send_calls)} read={read_send_calls}"
        )
    if re.search(
        r"(?i)Invoke-Expression|\biex\b|ScriptBlock\]::Create|\bAdd-Type\b|Start-Process|Start-Job|Invoke-Command|\.(?:Send|SendTo|WriteAsync|BeginWrite)\s*\(",
        text,
    ):
        raise ValidationError("PowerShell contains forbidden dynamic or secondary execution")
    if re.search(r"(?im)^\s*(?:&\s*)?(?:powershell|pwsh)(?:\.exe)?\b", text):
        raise ValidationError("PowerShell contains a secondary shell execution command")
    expected_netsh_call = re.findall(
        r'(?im)^\s*\$lines\s*=\s*&\s*netsh\.exe\s+wlan\s+show\s+interfaces\s+"name=\$\(\$interface\.Name\)"\s+2>\$null\s*$',
        text,
    )
    if len(expected_netsh_call) != 1 or text.count("&") != 1:
        raise ValidationError("PowerShell contains an unexpected call-operator execution site")

    integrity_calls = [
        match.start() for match in re.finditer(r"(?im)^\s*Assert-PackageIntegrity\s*$", text)
    ]
    if len(integrity_calls) != 2:
        raise ValidationError("runtime package-integrity check must occur at startup and again before reservation")
    integrity_body = _function_body(text, "Assert-PackageIntegrity")
    if "TARGET.json" not in integrity_body or "Get-FileSha256Hex" not in integrity_body:
        raise ValidationError("runtime package-integrity function does not verify TARGET.json file hashes")

    read_stop_body = _function_body(text, "New-PermanentReadStop")
    if "[System.IO.FileMode]::CreateNew" not in read_stop_body or ".Flush($true)" not in read_stop_body:
        raise ValidationError("permanent read-stop markers are not atomically and durably created")
    if re.search(
        r"(?im)^\s*if\s*\(\s*-not\s+\$packageExists\s+-or\s+-not\s+\$globalExists\s*\)\s*\{",
        read_stop_body,
    ) is None:
        raise ValidationError("both package and global permanent read-stop markers are not required")
    read_stop_calls = [
        match.start() for match in re.finditer(r"(?im)^\s*Assert-NoPermanentReadStop\s*$", text)
    ]
    if len(read_stop_calls) != 2:
        raise ValidationError("Write mode must check permanent read-stop markers twice")
    if len(re.findall(r"(?im)^\s*New-PermanentReadStop\s+-State\s+'ALREADY_CORRECT'", text)) != 1:
        raise ValidationError("exact target readback does not create one permanent no-write marker")
    if len(re.findall(r"(?im)^\s*New-PermanentReadStop\s+-State\s+'MISMATCH'", text)) != 1:
        raise ValidationError("non-target readback does not create one permanent mismatch marker")
    if len(re.findall(r"(?im)^\s*New-PermanentReadStop\s+-State\s+'INVALID_ENCODING'", text)) != 1:
        raise ValidationError("undecodable readback does not create one permanent invalid-encoding marker")
    if len(re.findall(r"(?im)^\s*Add-PersistentWriteAttemptEvent\s+-Event\s+'WRITE_NOT_SENT_BUT_LOCKED'", text)) != 1:
        raise ValidationError("locked-before-write failure does not append one WRITE_NOT_SENT_BUT_LOCKED event")
    if len(re.findall(r"WRITE_NOT_SENT_BUT_LOCKED:", text)) != 1:
        raise ValidationError("locked-before-write failure does not expose one unambiguous terminal status")
    if re.search(
        r"(?is)if\s*\(\$Mode\s*-eq\s*'Write'\s*-and\s*\$writeLockReserved\s*-and\s*-not\s*\$writeRequestSent\)\s*\{.*?WRITE_NOT_SENT_BUT_LOCKED",
        text,
    ) is None:
        raise ValidationError("WRITE_NOT_SENT_BUT_LOCKED is not gated by reservation and pre-send state")
    if re.search(r"(?i)if\s*\(\s*\$Mode\s*-eq\s*'SelfTest'\s*\)", text) is None:
        raise ValidationError("PowerShell has no explicit offline SelfTest mode gate")
    if re.search(r"(?i)if\s*\(\s*\$Mode\s*-eq\s*'Write'\s*\)", text) is None:
        raise ValidationError("PowerShell has no explicit Write-mode gate")
    lock_calls = [match.start() for match in re.finditer(r"(?im)^\s*New-PersistentWriteAttemptLock\s*$", text)]
    wifi_calls = [
        match.start() for match in re.finditer(r"(?im)^\s*\$wifi\s*=\s*Get-TargetWifiBinding\s*$", text)
    ]
    tcp_creations = [
        match.start()
        for match in re.finditer(r"(?im)^\s*\$client\s*=\s*New-Object\s+System\.Net\.Sockets\.TcpClient\s*$", text)
    ]
    write_dispatch_calls = [
        match.start()
        for match in re.finditer(r"(?im)^\s*Send-SingleAuthorizedWrite\s+-Stream\s+\$stream\b", text)
    ]
    if len(lock_calls) != 1 or len(tcp_creations) != 1 or lock_calls[0] >= tcp_creations[0]:
        raise ValidationError("atomic write reservation is not a unique main-path call before TcpClient creation")
    if len(wifi_calls) != 2 or len(write_dispatch_calls) != 1:
        raise ValidationError("audited Wi-Fi recheck or unique write-dispatch call site is missing")
    outer_try_anchor = text.find("$client = $null\ntry {")
    outer_catch_anchor = text.find("$outerErrorMessage = $_.Exception.Message")
    outer_finally_anchor = text.rfind("\nfinally {")
    if not (
        0 <= outer_try_anchor < lock_calls[0] < tcp_creations[0] < write_dispatch_calls[0]
        < outer_catch_anchor < outer_finally_anchor
    ):
        raise ValidationError("the outer try/catch does not cover every post-reservation pre-write failure site")
    self_test_gate = re.search(
        r"(?is)if\s*\(\s*\$Mode\s*-eq\s*'SelfTest'\s*\)\s*\{(.*?)\}", text
    )
    if self_test_gate is None or re.search(
        r"(?im)^\s*(?:return|exit\s+0)\s*$", self_test_gate.group(1)
    ) is None:
        raise ValidationError("SelfTest gate does not exit before the network-capable main path")
    if self_test_gate.start() >= tcp_creations[0]:
        raise ValidationError("SelfTest gate occurs after TcpClient creation")
    read_self_test_calls = [
        match.start()
        for match in re.finditer(r"(?im)^\s*Assert-ReadOnlyProtocolSelfTest\s*$", text)
    ]
    if len(read_self_test_calls) != 1 or read_self_test_calls[0] >= self_test_gate.start():
        raise ValidationError("read-only protocol SelfTest is not a unique pre-network call")
    if not (
        integrity_calls[0]
        < self_test_gate.start()
        < read_stop_calls[0]
        < wifi_calls[0]
        < wifi_calls[1]
        < integrity_calls[1]
        < read_stop_calls[1]
        < lock_calls[0]
        < tcp_creations[0]
        < write_dispatch_calls[0]
    ):
        raise ValidationError(
            "startup, permanent-stop checks, Wi-Fi recheck, integrity recheck, reservation, TCP, and write dispatch are not in the audited order"
        )

    # A diagnostic path must not dispatch to the only write-send function.  This
    # is intentionally conservative: it checks the main mode block between the
    # Diagnostic and Query branches in the audited generated structure.
    diagnostic_match = re.search(
        r"(?is)if\s*\(\s*\$Mode\s*-eq\s*'Diagnostic'\s*\)(.*?)(?=if\s*\(\s*\$Mode\s*-eq\s*'Query')",
        text,
    )
    if diagnostic_match is None:
        raise ValidationError("PowerShell Diagnostic/Query mode ordering could not be audited")
    diagnostic_body = diagnostic_match.group(1)
    diagnostic_required = (
        r"(?im)^\s*\[byte\[\]\]\$diagnosticInner\s*=\s*New-ReadOnlySnPacket\s+-Counter\s+1\s*$",
        r"(?im)^\s*\[byte\[\]\]\$diagnosticPacket\s*=\s*New-TransportPacket\s+-InnerBody\s+\$diagnosticInner\s+-MessageId\s+0\s*$",
        r"(?im)^\s*Assert-ReadOnlyDiagnosticPacket\s+-Inner\s+\$diagnosticInner\s+-Packet\s+\$diagnosticPacket\s*$",
        r"(?im)^\s*Send-Packet\s+-Stream\s+\$stream\s+-Packet\s+\$diagnosticPacket\s*$",
    )
    if any(len(re.findall(pattern, diagnostic_body)) != 1 for pattern in diagnostic_required):
        raise ValidationError("PowerShell Diagnostic branch is not the exact audited read-only packet sequence")
    if re.search(
        r"(?i)Send-SingleAuthorizedWrite|0x41|\b65\b|New-TargetWriteInnerPacket|Assert-TargetWritePacket|TargetEncodedSn|BlockCopy|\.(?:Send|SendTo|Write|WriteAsync|BeginWrite)\s*\(|powershell(?:\.exe)?",
        diagnostic_body,
    ):
        raise ValidationError("PowerShell Diagnostic branch contains a write-capable construction or alternate sender")

    query_match = re.search(
        r"(?is)if\s*\(\s*\$Mode\s*-eq\s*'Query'\s*-or\s*\$Mode\s*-eq\s*'PostWriteCheck'\s*\)(.*?)(?=if\s*\(\s*\$Mode\s*-ne\s*'Write'\s*\))",
        text,
    )
    if query_match is None:
        raise ValidationError("PowerShell Query/PostWriteCheck branch could not be audited")
    query_body = query_match.group(1)
    query_required = (
        r"(?im)^\s*\[byte\[\]\]\$inner\s*=\s*New-ReadOnlySnPacket\s+-Counter\s+\$counter\s*$",
        r"(?im)^\s*\[byte\[\]\]\$packet\s*=\s*New-TransportPacket\s+-InnerBody\s+\$inner\s+-MessageId\s+\$messageId\s*$",
        r"(?im)^\s*Assert-ReadOnlyDiagnosticPacket\s+-Inner\s+\$inner\s+-Packet\s+\$packet\s*$",
        r"(?im)^\s*Send-Packet\s+-Stream\s+\$stream\s+-Packet\s+\$packet\s*$",
    )
    if any(len(re.findall(pattern, query_body)) != 1 for pattern in query_required):
        raise ValidationError("PowerShell Query/PostWriteCheck branch is not the exact audited read-only packet sequence")
    if re.search(
        r"(?i)Send-SingleAuthorizedWrite|0x41|\b65\b|New-TargetWriteInnerPacket|Assert-TargetWritePacket|TargetEncodedSn|BlockCopy|\.(?:Send|SendTo|Write|WriteAsync|BeginWrite)\s*\(|powershell(?:\.exe)?|\$(?:inner|packet)\s*\[.*?\]\s*=",
        query_body,
    ):
        raise ValidationError("PowerShell Query/PostWriteCheck branch contains a write-capable construction, mutation, or alternate sender")

    verification_required = (
        r"(?im)^\s*\[byte\[\]\]\$readInner\s*=\s*New-ReadOnlySnPacket\s+-Counter\s+\$counter\s*$",
        r"(?im)^\s*\[byte\[\]\]\$readPacket\s*=\s*New-TransportPacket\s+-InnerBody\s+\$readInner\s+-MessageId\s+\$messageId\s*$",
        r"(?im)^\s*Assert-ReadOnlyDiagnosticPacket\s+-Inner\s+\$readInner\s+-Packet\s+\$readPacket\s*$",
        r"(?im)^\s*Send-Packet\s+-Stream\s+\$stream\s+-Packet\s+\$readPacket\s*$",
    )
    if any(len(re.findall(pattern, text)) != 1 for pattern in verification_required):
        raise ValidationError("post-write verification is not the exact audited read-only packet sequence")
    if re.search(r"(?im)^\s*\$(?:readInner|readPacket)\s*\[.*?\]\s*=", text):
        raise ValidationError("post-write read-only packet variables are mutated after construction")
    return script


def _validate_archive(package_directory: Path, expected_files: list[str], archive_path: Path | None) -> dict[str, str] | None:
    if archive_path is None:
        candidate = package_directory.parent / f"{package_directory.name}.zip"
        archive_path = candidate if candidate.is_file() else None
    if archive_path is None:
        return None
    archive_path = archive_path.expanduser().resolve()
    if not archive_path.is_file():
        raise ValidationError(f"archive is missing: {archive_path}")
    sha_path = archive_path.with_name(f"{archive_path.name}.sha256")
    if not sha_path.is_file():
        raise ValidationError(f"archive SHA-256 sidecar is missing: {sha_path}")
    actual_archive_hash = _sha256_file(archive_path)
    expected_line = f"{actual_archive_hash}  {archive_path.name}"
    if sha_path.read_text(encoding="ascii").strip() != expected_line:
        raise ValidationError("archive SHA-256 sidecar does not match the archive")

    expected_members = {f"{package_directory.name}/{relative}" for relative in expected_files}
    with zipfile.ZipFile(archive_path, "r") as archive:
        infos = archive.infolist()
        names = [info.filename for info in infos if not info.is_dir()]
        if len(names) != len(set(names)):
            raise ValidationError("archive contains duplicate member names")
        for info in infos:
            pure = PurePosixPath(info.filename)
            if pure.is_absolute() or ".." in pure.parts or info.flag_bits & 0x1:
                raise ValidationError(f"archive contains unsafe or encrypted member: {info.filename}")
            if ((info.external_attr >> 16) & 0o170000) == 0o120000:
                raise ValidationError(f"archive contains a symbolic-link member: {info.filename}")
        if set(names) != expected_members:
            raise ValidationError("archive members do not exactly match the package directory")
        for name in names:
            relative = PurePosixPath(name).relative_to(package_directory.name).as_posix()
            disk_path = package_directory / Path(*PurePosixPath(relative).parts)
            if hashlib.sha256(archive.read(name)).hexdigest() != _sha256_file(disk_path):
                raise ValidationError(f"archive member differs from package directory: {name}")
    return {
        "archive": str(archive_path),
        "archiveSha256": actual_archive_hash,
        "sha256File": str(sha_path),
    }


def _run_powershell_self_test(script: Path, timeout_seconds: int) -> dict[str, Any]:
    executable = shutil.which("powershell.exe") or shutil.which("powershell")
    if executable is None:
        raise ValidationError("Windows PowerShell is required to run the generated package SelfTest")
    environment = os.environ.copy()
    environment["MIDEA_SN_RESTORE_VALIDATION"] = "OFFLINE_SELFTEST_ONLY"
    try:
        completed = subprocess.run(
            [
                executable,
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(script),
                "-Mode",
                "SelfTest",
            ],
            cwd=str(script.parent),
            env=environment,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise ValidationError(f"PowerShell SelfTest exceeded {timeout_seconds} seconds") from exc
    output = (completed.stdout + "\n" + completed.stderr).strip()
    if completed.returncode != 0:
        raise ValidationError(f"PowerShell SelfTest failed with exit {completed.returncode}: {output}")
    if re.search(r"(?is)self[ -]?test.*pass", output) is None:
        raise ValidationError(f"PowerShell SelfTest returned success without an explicit PASS result: {output}")
    return {"exitCode": completed.returncode, "output": output}


def validate(package: Path, archive: Path | None, timeout_seconds: int, require_archive: bool) -> dict[str, Any]:
    package_directory = package.expanduser().resolve()
    if not package_directory.is_dir():
        raise ValidationError(f"package directory does not exist: {package_directory}")
    manifest = _load_manifest(package_directory)
    identity = _validate_manifest(manifest)
    expected_files = _validate_file_hashes(package_directory, manifest)
    _validate_launchers(package_directory)
    script = _validate_powershell(package_directory, identity)
    archive_result = _validate_archive(package_directory, expected_files, archive)
    if require_archive and archive_result is None:
        raise ValidationError("archive validation was required, but no sibling ZIP was found and --archive was omitted")
    self_test = _run_powershell_self_test(script, timeout_seconds)
    return {
        "result": "PACKAGE_VALID",
        "packageDirectory": str(package_directory),
        "incidentId": identity["incidentId"],
        "targetSn": identity["sn"],
        "serviceSsid": identity["ssid"],
        "filesVerified": len(expected_files),
        "archive": archive_result,
        "powerShellSelfTest": self_test,
        "networkActionsPerformed": False,
    }


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Validate manifest, static safety invariants, file/archive hashes, and offline PowerShell SelfTest"
    )
    parser.add_argument("package", type=Path, help="generated package directory containing TARGET.json")
    parser.add_argument("--archive", type=Path, help="ZIP to validate; otherwise a sibling <package>.zip is used if present")
    parser.add_argument("--require-archive", action="store_true", help="fail if no archive is available")
    parser.add_argument("--self-test-timeout", type=int, default=60, choices=range(5, 121), metavar="SECONDS")
    return parser


def main() -> int:
    arguments = _build_parser().parse_args()
    try:
        result = validate(
            arguments.package,
            arguments.archive,
            arguments.self_test_timeout,
            arguments.require_archive,
        )
    except (ValidationError, OSError, ValueError, zipfile.BadZipFile) as exc:
        print(f"PACKAGE_INVALID: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
