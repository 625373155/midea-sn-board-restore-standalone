from __future__ import annotations

"""Command-line interface for the offline standalone release.

This module never joins Wi-Fi, creates a socket, runs a generated launcher, or
sends an appliance frame.  It only gathers evidence, generates immutable files,
validates those files, runs protocol regression tests, and displays masked local
history.
"""

import argparse
import json
import sys
import zipfile
from pathlib import Path
from typing import Any, Callable, Sequence

from . import __version__, generator, protocol, validator


InputFunction = Callable[[str], str]
OutputFunction = Callable[[str], None]


class WizardCancelled(RuntimeError):
    """The interactive evidence gate was not confirmed."""


def _confirm_exact(input_fn: InputFunction, prompt: str, phrase: str) -> None:
    if input_fn(f"{prompt}\n请输入 {phrase}：") != phrase:
        raise WizardCancelled(f"未输入精确确认短语 {phrase}；未生成任何恢复包")


def _ask_required(input_fn: InputFunction, prompt: str) -> str:
    value = input_fn(f"{prompt}：")
    if value == "":
        raise WizardCancelled(f"{prompt}不能为空；未生成任何恢复包")
    return value


def _mask_sn(value: Any) -> str | None:
    if not isinstance(value, str) or len(value) < 8:
        return None
    return f"{value[:2]}{'*' * max(0, len(value) - 6)}{value[-4:]}"


def _mask_ssid(value: Any) -> str | None:
    if not isinstance(value, str) or len(value) < 4:
        return None
    return f"midea_test_********{value[-4:]}" if value.lower().startswith("midea_test_") else "<masked>"


def _history_records() -> tuple[Path, list[dict[str, Any]]]:
    state = generator._local_state_directory()
    path = state / "events.jsonl"
    return path, generator._read_history(path)


def run_wizard(
    *, input_fn: InputFunction = input, output_fn: OutputFunction = print
) -> dict[str, Any]:
    output_fn("美的空调替换主板 SN 恢复包离线向导")
    output_fn("本向导不连接设备、不发送查询或写入。它只生成一个受锁定的本机执行包。")
    output_fn("仅适用于：本人所有/获授权的美的空调、真实更换的新主板、可信来源的原机身 22 位 SN。")
    _confirm_exact(input_fn, "确认你是设备所有者或获授权维修人", "I-OWN-OR-AM-AUTHORIZED")
    _confirm_exact(input_fn, "确认目标产品是美的空调（不是其他家电）", "MIDEA-AIR-CONDITIONER")

    sn = _ask_required(input_fn, "原机身 SN（精确 22 位 ASCII 数字，不能填 App 的 32 位显示值）")
    source = _ask_required(
        input_fn,
        "SN 可信来源（customer-service / original-label / old-app / old-board）",
    )
    if source not in generator.SOURCE_CHOICES:
        raise WizardCancelled("SN 来源选项无效；未生成任何恢复包")
    source_reference = _ask_required(input_fn, "SN 来源凭据说明（一行文字，不要再次填写 SN）")
    model = _ask_required(input_fn, "本机准确型号（本版本仅支持 KFR-26G/WXAA2@）")
    ssid = _ask_required(input_fn, "当前新主板实时广播的完整服务热点名 midea_test_<12 个十六进制字符>")
    bssid = input_fn("BSSID（可选；不知道直接回车）：") or None
    new_board_evidence = _ask_required(input_fn, "本次实体换板凭据说明（一行文字）")
    _confirm_exact(input_fn, "确认这是一次真实的新实体主板更换事件", "NEW-PHYSICAL-BOARD-CONFIRMED")
    _confirm_exact(input_fn, "确认输入的是可信来源的原机身 SN", "TRUSTED-ORIGINAL-SN-CONFIRMED")
    output = _ask_required(input_fn, "输出父目录（必须在本项目目录之外）")

    previous_incident_id: str | None = None
    later_event_confirmed = False
    try:
        normalized_ssid = generator._validate_ssid(ssid)[1]
        history_path, history = _history_records()
        priors = generator._matching_prior_events(sn, normalized_ssid, history)
    except (generator.GenerationError, OSError, ValueError):
        priors = []
        history_path = generator._local_state_directory() / "events.jsonl"
    if priors:
        latest = str(priors[-1].get("incidentId", ""))
        output_fn(f"检测到相同 SN 或热点的本机历史，最新事件 ID：{latest}")
        output_fn(f"历史文件：{history_path}")
        output_fn("这不能作为重试理由。只有后来又真实更换了一块实体主板，才可建立新事件。")
        previous_incident_id = _ask_required(input_fn, "请输入上面显示的最新事件 ID")
        _confirm_exact(
            input_fn,
            "确认历史事件之后又发生了一次新的实体主板更换，并且当前凭据是新的",
            "LATER-PHYSICAL-BOARD-REPLACEMENT-CONFIRMED",
        )
        later_event_confirmed = True

    arguments = argparse.Namespace(
        sn=sn,
        ssid=ssid,
        model=model,
        bssid=bssid,
        sn_source=source,
        sn_source_reference=source_reference,
        new_board_evidence=new_board_evidence,
        ownership_confirmed=True,
        trusted_source_confirmed=True,
        new_physical_board_confirmed=True,
        later_physical_board_event_confirmed=later_event_confirmed,
        previous_incident_id=previous_incident_id,
        output=output,
    )
    result = generator.generate(arguments)
    output_fn(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    output_fn("生成器未连接设备，也没有运行生成包。请先用 validate 命令校验，再阅读包内中文说明。")
    return result


def _add_generation_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--sn", required=True, help="精确 22 位 ASCII 数字原机身 SN；拒绝 App 的 32 位值")
    parser.add_argument("--ssid", required=True, help="实时服务 SSID：midea_test_<12 hex>")
    parser.add_argument(
        "--model",
        required=True,
        choices=generator.COMPATIBLE_MODELS,
        help="本机准确型号；本版本仅支持 KFR-26G/WXAA2@",
    )
    parser.add_argument("--bssid", help="可选的实时 BSSID")
    parser.add_argument("--sn-source", required=True, choices=generator.SOURCE_CHOICES)
    parser.add_argument("--sn-source-reference", required=True, help="一行凭据说明，不要再写 SN")
    parser.add_argument("--new-board-evidence", required=True, help="一行本次实体换板凭据说明")
    parser.add_argument("--ownership-confirmed", action="store_true")
    parser.add_argument("--trusted-source-confirmed", action="store_true")
    parser.add_argument("--new-physical-board-confirmed", action="store_true")
    parser.add_argument("--later-physical-board-event-confirmed", action="store_true")
    parser.add_argument("--previous-incident-id")
    parser.add_argument("--output", required=True, help="本项目目录之外的输出父目录")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="midea_sn_restore_cli.py",
        description=(
            "美的空调替换主板 body-SN 恢复包离线工具。工具本身不连接设备；"
            "只生成、校验和审计单设备一次性恢复包。"
        ),
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("wizard", help="交互式收集全部资格证据并生成包")
    generate_parser = subparsers.add_parser("generate", help="使用显式参数离线生成包")
    _add_generation_arguments(generate_parser)

    validate_parser = subparsers.add_parser("validate", help="校验目录、ZIP、哈希、模板和离线 PowerShell 自检")
    validate_parser.add_argument("package", type=Path)
    validate_parser.add_argument("--archive", type=Path)
    validate_parser.add_argument("--require-archive", action="store_true")
    validate_parser.add_argument("--self-test-timeout", type=int, default=60, choices=range(5, 121), metavar="SECONDS")

    subparsers.add_parser("self-test", help="运行协议回归和静态安全自检，不连接设备")
    history_parser = subparsers.add_parser("history", help="只读显示本机生成历史（身份默认掩码）")
    history_parser.add_argument("--json", action="store_true", help="输出掩码后的 JSON")
    return parser


def _run_self_test() -> dict[str, Any]:
    protocol.self_test()
    if generator.IMMUTABLE_PRIOR_EVENTS:
        raise AssertionError("public source must not embed any device incident history")
    if generator.COMPATIBLE_MODELS != ("KFR-26G/WXAA2@",):
        raise AssertionError("generator model allowlist changed without compatibility review")
    if validator.COMPATIBLE_MODELS != generator.COMPATIBLE_MODELS:
        raise AssertionError("generator and validator model allowlists differ")
    if validator.EXPECTED_EVIDENCE_HASH_VERSION != generator.EVIDENCE_HASH_VERSION:
        raise AssertionError("generator and validator evidence-hash versions differ")
    template_names = {path.name for path in generator.TEMPLATE_DIRECTORY.iterdir() if path.is_file()}
    required = {
        "00_READ_ME_FIRST.txt.tmpl",
        "00_self_test.cmd.tmpl",
        "01_query_only.cmd.tmpl",
        "02_restore_once_and_verify.cmd.tmpl",
        "03_raw_read_only_diagnostic.cmd.tmpl",
        "04_post_write_read_only_check.cmd.tmpl",
        "midea_sn_restore.ps1.tmpl",
        "使用说明.md.tmpl",
    }
    if template_names != required:
        raise AssertionError(f"template set mismatch: {sorted(template_names)}")
    generator_source = Path(generator.__file__).read_text(encoding="utf-8-sig")
    forbidden_imports = ("import socket", "from socket", "import requests", "import urllib")
    if any(item in generator_source for item in forbidden_imports):
        raise AssertionError("offline generator contains a network import")
    runtime_template = (generator.TEMPLATE_DIRECTORY / "midea_sn_restore.ps1.tmpl").read_text(
        encoding="utf-8-sig"
    )
    for required_runtime_gate in (
        "ConvertFrom-EncodedBodySn",
        "READ-INVALID-DO-NOT-WRITE",
        "WRITE_NOT_SENT_BUT_LOCKED",
    ):
        if required_runtime_gate not in runtime_template:
            raise AssertionError(f"runtime template lacks safety gate: {required_runtime_gate}")
    return {
        "result": "SELF_TEST_OK",
        "protocolVectors": len(protocol.ENCODING_VECTORS),
        "templates": len(template_names),
        "embeddedDeviceHistory": 0,
        "networkActionsPerformed": False,
    }


def _show_history(as_json: bool, output_fn: OutputFunction = print) -> int:
    path, records = _history_records()
    masked = [
        {
            "incidentId": record.get("incidentId"),
            "previousIncidentId": record.get("previousIncidentId"),
            "status": record.get("status") or record.get("outcome"),
            "targetSn": _mask_sn(record.get("targetSn")),
            "serviceSsid": _mask_ssid(record.get("expectedServiceSsid")),
            "model": record.get("model"),
            "generatedUtc": record.get("generatedUtc") or record.get("recordedDate"),
        }
        for record in records
    ]
    if as_json:
        output_fn(json.dumps({"historyFile": str(path), "records": masked}, ensure_ascii=False, indent=2))
    else:
        output_fn(f"历史文件：{path}")
        if not masked:
            output_fn("没有本机生成历史。")
        for record in masked:
            output_fn(
                " | ".join(
                    str(record.get(key) or "-")
                    for key in ("incidentId", "status", "targetSn", "serviceSsid", "generatedUtc")
                )
            )
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _build_parser().parse_args(argv)
    try:
        if arguments.command == "wizard":
            run_wizard()
            return 0
        if arguments.command == "generate":
            result = generator.generate(arguments)
        elif arguments.command == "validate":
            result = validator.validate(
                arguments.package,
                arguments.archive,
                arguments.self_test_timeout,
                arguments.require_archive,
            )
        elif arguments.command == "self-test":
            result = _run_self_test()
        elif arguments.command == "history":
            return _show_history(arguments.json)
        else:  # pragma: no cover - argparse guarantees a known command
            raise AssertionError(f"unhandled command: {arguments.command}")
    except (
        WizardCancelled,
        generator.GenerationError,
        validator.ValidationError,
        AssertionError,
        OSError,
        ValueError,
        zipfile.BadZipFile,
    ) as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
