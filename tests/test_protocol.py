import json
import unittest
from pathlib import Path

from midea_sn_restore import protocol


SYNTHETIC_SN = "1234567890123456789012"


class ProtocolTests(unittest.TestCase):
    def test_reference_self_test(self) -> None:
        protocol.self_test()

    def test_only_public_positive_identity(self) -> None:
        self.assertEqual(set(protocol.ENCODING_VECTORS), {SYNTHETIC_SN})
        corpus = json.loads(Path(protocol.__file__).with_name("test_vectors.json").read_text(encoding="utf-8"))
        self.assertTrue(corpus["synthetic_only"])
        self.assertEqual(
            {item["body_sn"] for item in corpus["encoding_vectors"]},
            {SYNTHETIC_SN},
        )
        self.assertEqual(
            {item["input"] for item in corpus["ssid_vectors"]["valid"]},
            {"midea_test_a1b2c3d4e5f6"},
        )

    def test_encoding_round_trip(self) -> None:
        encoded = protocol.encode_sn(SYNTHETIC_SN)
        self.assertEqual(len(encoded), 22)
        self.assertEqual(protocol.decode_sn(encoded), SYNTHETIC_SN)

    def test_invalid_values_are_rejected(self) -> None:
        invalid = (
            "",
            "123456789012345678901",
            "12345678901234567890123",
            "12345678901234567890O2",
            " 1234567890123456789012",
            "00000012345678901234567890120000",
            "１２３４５６７８９０１２３４５６７８９０１２",
        )
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(ValueError):
                protocol.validate_body_sn(value)

    def test_decode_domain_errors_are_value_errors(self) -> None:
        invalid_encoded = (
            "x" * 22,
            bytes(21),
            bytes(22),
            bytes((46, *([0x11] * 20), 0)),
            bytes((36, *([0x11] * 20), 10)),
            bytes((36, *([0x40] * 20), 0)),
        )
        for value in invalid_encoded:
            with self.subTest(value=repr(value)), self.assertRaises(ValueError):
                protocol.decode_sn(value)  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
