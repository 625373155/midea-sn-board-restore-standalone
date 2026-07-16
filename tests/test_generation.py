import argparse
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from midea_sn_restore import generator, validator


SYNTHETIC_SN = "1234567890123456789012"
SYNTHETIC_SSID = "midea_test_a1b2c3d4e5f6"
COMPATIBLE_MODEL = "KFR-26G/WXAA2@"


def generation_arguments(output: Path) -> argparse.Namespace:
    return argparse.Namespace(
        sn=SYNTHETIC_SN,
        ssid=SYNTHETIC_SSID,
        model=COMPATIBLE_MODEL,
        bssid=None,
        sn_source="customer-service",
        sn_source_reference="synthetic customer-service regression reference",
        new_board_evidence="synthetic physical replacement regression evidence",
        ownership_confirmed=True,
        trusted_source_confirmed=True,
        new_physical_board_confirmed=True,
        later_physical_board_event_confirmed=False,
        previous_incident_id=None,
        output=str(output),
    )


class GenerationTests(unittest.TestCase):
    def test_generate_validate_and_lock_repeat(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = root / "state"
            output = root / "output"
            with mock.patch.object(generator, "_local_state_directory", return_value=state):
                result = generator.generate(generation_arguments(output))
                package = Path(result["packageDirectory"])
                archive = Path(result["archive"])
                manifest = json.loads((package / "TARGET.json").read_text(encoding="utf-8"))
                self.assertEqual(manifest["target"]["bodySn"], SYNTHETIC_SN)
                self.assertEqual(manifest["target"]["model"], COMPATIBLE_MODEL)
                self.assertEqual(manifest["network"]["expectedServiceSsid"], SYNTHETIC_SSID)
                self.assertTrue(archive.is_file())
                self.assertEqual(manifest["generator"]["version"], "1.3.0")
                self.assertEqual(
                    manifest["repairEvent"]["newBoardEvidenceHashVersion"],
                    generator.EVIDENCE_HASH_VERSION,
                )
                self.assertRegex(manifest["repairEvent"]["newBoardEvidenceSha256"], r"^[0-9a-f]{64}$")

                if shutil.which("powershell.exe") or shutil.which("powershell") or shutil.which("pwsh"):
                    validation = validator.validate(package, archive, 60, True)
                    self.assertEqual(validation["result"], "PACKAGE_VALID")
                    self.assertFalse(validation["networkActionsPerformed"])

                second_output = root / "second-output"
                with self.assertRaises(generator.GenerationError):
                    generator.generate(generation_arguments(second_output))

    def test_evidence_variants_cannot_claim_a_fresh_board_event(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = root / "state"
            first = generation_arguments(root / "first")
            first.new_board_evidence = "Synthetic ＡC Board   Evidence"
            with mock.patch.object(generator, "_local_state_directory", return_value=state):
                first_result = generator.generate(first)
                second = generation_arguments(root / "second")
                second.new_board_evidence = "synthetic ac board evidence"
                second.previous_incident_id = first_result["incidentId"]
                second.later_physical_board_event_confirmed = True
                with self.assertRaisesRegex(generator.GenerationError, "evidence is identical"):
                    generator.generate(second)

    def test_unversioned_prior_evidence_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = root / "state"
            state.mkdir()
            legacy_id = "legacy-synthetic-audit"
            legacy = {
                "incidentId": legacy_id,
                "targetSn": SYNTHETIC_SN,
                "expectedServiceSsid": SYNTHETIC_SSID,
                "newBoardEvidenceSha256": "1" * 64,
            }
            (state / "events.jsonl").write_text(json.dumps(legacy) + "\n", encoding="utf-8")
            arguments = generation_arguments(root / "output")
            arguments.previous_incident_id = legacy_id
            arguments.later_physical_board_event_confirmed = True
            with mock.patch.object(generator, "_local_state_directory", return_value=state):
                with self.assertRaisesRegex(generator.GenerationError, "unversioned evidence hash"):
                    generator.generate(arguments)

    def test_validator_rejects_evidence_hash_inconsistency(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with mock.patch.object(generator, "_local_state_directory", return_value=root / "state"):
                result = generator.generate(generation_arguments(root / "output"))
            package = Path(result["packageDirectory"])
            target_path = package / "TARGET.json"
            manifest = json.loads(target_path.read_text(encoding="utf-8"))
            manifest["repairEvent"]["newBoardEvidenceSha256"] = "0" * 64
            target_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
            with self.assertRaisesRegex(validator.ValidationError, "normalized hash"):
                validator.validate(package, Path(result["archive"]), 60, True)

    def test_tampered_package_fails_validation_before_self_test(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with mock.patch.object(generator, "_local_state_directory", return_value=root / "state"):
                result = generator.generate(generation_arguments(root / "output"))
            package = Path(result["packageDirectory"])
            target = package / "00_READ_ME_FIRST.txt"
            target.write_text(target.read_text(encoding="utf-8-sig") + "\nTAMPERED\n", encoding="utf-8")
            with self.assertRaises(validator.ValidationError):
                validator.validate(package, Path(result["archive"]), 60, True)

    def test_validator_rejects_model_outside_allowlist(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with mock.patch.object(generator, "_local_state_directory", return_value=root / "state"):
                result = generator.generate(generation_arguments(root / "output"))
            package = Path(result["packageDirectory"])
            target_path = package / "TARGET.json"
            manifest = json.loads(target_path.read_text(encoding="utf-8"))
            manifest["target"]["model"] = "KFR-35G/UNVERIFIED"
            target_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
            with self.assertRaisesRegex(validator.ValidationError, "compatibility allowlist"):
                validator.validate(package, Path(result["archive"]), 60, True)


if __name__ == "__main__":
    unittest.main()
