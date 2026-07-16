import io
import unittest
from pathlib import Path
from unittest import mock

from midea_sn_restore import cli, generator


class CliTests(unittest.TestCase):
    def test_self_test_has_no_network_action(self) -> None:
        result = cli._run_self_test()
        self.assertEqual(result["result"], "SELF_TEST_OK")
        self.assertFalse(result["networkActionsPerformed"])
        self.assertEqual(result["embeddedDeviceHistory"], 0)
        self.assertEqual(result["protocolVectors"], 1)

    def test_wizard_stops_before_generation_without_exact_authorization(self) -> None:
        answers = iter(["no"])
        output: list[str] = []
        with mock.patch.object(generator, "generate") as generate:
            with self.assertRaises(cli.WizardCancelled):
                cli.run_wizard(input_fn=lambda _prompt: next(answers), output_fn=output.append)
        generate.assert_not_called()

    def test_history_output_masks_identity(self) -> None:
        records = [
            {
                "incidentId": "12345678-1234-4123-8123-123456789abc",
                "status": "PACKAGE_GENERATED_NOT_EXECUTED",
                "targetSn": "1234567890123456789012",
                "expectedServiceSsid": "midea_test_a1b2c3d4e5f6",
                "generatedUtc": "2030-01-01T00:00:00Z",
            }
        ]
        output: list[str] = []
        with mock.patch.object(cli, "_history_records", return_value=(Path("history.jsonl"), records)):
            self.assertEqual(cli._show_history(False, output.append), 0)
        rendered = "\n".join(output)
        self.assertNotIn("1234567890123456789012", rendered)
        self.assertNotIn("midea_test_a1b2c3d4e5f6", rendered)
        self.assertIn("9012", rendered)
        self.assertIn("e5f6", rendered)

    def test_main_self_test(self) -> None:
        with mock.patch("sys.stdout", new_callable=io.StringIO) as stdout:
            self.assertEqual(cli.main(["self-test"]), 0)
        self.assertIn("SELF_TEST_OK", stdout.getvalue())

    def test_model_allowlist_is_exact(self) -> None:
        self.assertEqual(generator.COMPATIBLE_MODELS, ("KFR-26G/WXAA2@",))
        self.assertEqual(generator._validate_model("KFR-26G/WXAA2@"), "KFR-26G/WXAA2@")
        with self.assertRaises(generator.GenerationError):
            generator._validate_model("KFR-35G/UNVERIFIED")


if __name__ == "__main__":
    unittest.main()

