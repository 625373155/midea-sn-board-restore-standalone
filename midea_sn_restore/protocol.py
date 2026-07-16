from __future__ import annotations

import argparse
import base64
import json
import os
import re
import struct
import subprocess
from pathlib import Path
from typing import Iterable


AES_KEY = b"d4d5jljeiasdrc33"

S1 = bytes.fromhex(
    "05 24 21 27 03 10 35 14 16 3B 11 23 26 06 3E 33 "
    "1C 13 30 28 3F 3A 0E 2A 1D 22 1A 3C 07 31 0A 19 "
    "36 0F 2E 08 1F 12 32 2C 2D 25 09 01 0B 0C 15 04 "
    "0D 00 18 34 3D 39 38 20 2F 37 2B 29 17 1B 1E 02"
)

S2 = bytes.fromhex(
    "39 31 29 21 19 11 09 01 3B 33 2B 23 1B 13 0B 03 "
    "3D 35 2D 25 1D 15 0D 05 3F 37 2F 27 1F 17 0F 07 "
    "38 30 28 20 18 10 08 00 3A 32 2A 22 1A 12 0A 02 "
    "3C 34 2C 24 1C 14 0C 04 3E 36 2E 26 1E 16 0E 06"
)

P = (
    (18, 4, 6, 8, 10, 12, 17, 0, 7, 9, 14, 13, 3, 16, 5, 19, 11, 15, 1, 2),
    (5, 17, 0, 19, 10, 11, 18, 6, 2, 13, 4, 3, 14, 15, 9, 12, 1, 7, 16, 8),
    (1, 3, 10, 7, 0, 6, 4, 18, 12, 8, 15, 2, 17, 16, 9, 11, 19, 5, 14, 13),
    (7, 17, 1, 16, 19, 18, 2, 13, 4, 5, 6, 9, 11, 14, 8, 15, 3, 10, 12, 0),
    (10, 16, 8, 7, 18, 9, 0, 2, 11, 13, 3, 17, 6, 5, 4, 19, 14, 1, 12, 15),
    (5, 4, 6, 12, 8, 3, 14, 17, 9, 2, 19, 18, 15, 1, 7, 13, 0, 10, 11, 16),
    (10, 18, 3, 1, 15, 0, 4, 16, 7, 14, 8, 6, 19, 9, 5, 2, 13, 17, 12, 11),
    (10, 19, 16, 6, 2, 5, 14, 17, 9, 1, 15, 13, 11, 8, 4, 3, 0, 7, 18, 12),
    (12, 7, 11, 14, 18, 3, 8, 6, 4, 13, 2, 17, 5, 16, 9, 15, 0, 1, 10, 19),
    (18, 13, 15, 2, 3, 7, 16, 0, 19, 1, 11, 8, 17, 14, 10, 9, 5, 12, 4, 6),
)

ENCODING_VECTORS = {
    "1234567890123456789012": "25 14 30 00 00 0D 26 1D 3D 18 14 21 1D 11 18 11 30 3D 21 26 0D 02",
}

KNOWN_WRITE_INNER = (
    "AA 24 AC 00 00 00 00 00 01 0F 80 41 25 14 30 00 00 0D 26 1D 3D 18 14 "
    "21 1D 11 18 11 30 3D 21 26 0D 02 01 72 8F"
)
KNOWN_WRITE_CIPHER = (
    "55 9E D5 96 DE 32 48 55 B2 F4 F1 5D B0 B0 F6 91 37 A6 36 42 DA 7B 6C A1 "
    "54 C0 BC 88 82 D8 F9 D4 CF 3C E2 77 FC 5A 09 EF 14 FA AC E6 B6 0F 32 1F"
)


def hex_bytes(data: bytes | bytearray | Iterable[int]) -> str:
    return " ".join(f"{value:02X}" for value in data)


def validate_body_sn(sn: str) -> str:
    if not isinstance(sn, str) or re.fullmatch(r"[0-9]{22}", sn) is None:
        raise ValueError("body SN must contain exactly 22 ASCII digits; 32-digit App SNs are rejected")
    return sn


def encode_sn(sn: str) -> bytes:
    validate_body_sn(sn)
    values = [ord(char) - 0x30 for char in sn]
    temporary = [S1[values[index + 1]] for index in range(20)]
    key = min(values[21], 9)
    for index in range(20):
        values[1 + P[key][index]] = temporary[index]

    output = bytearray(22)
    for index in range(1, 21):
        output[index] = S2[values[index]]
    output[0] = values[0] + 36
    output[21] = values[21]
    return bytes(output)


def decode_sn(encoded: bytes) -> str:
    if not isinstance(encoded, (bytes, bytearray)):
        raise ValueError("encoded body SN must be bytes-like")
    if len(encoded) != 22:
        raise ValueError("encoded body SN must be exactly 22 bytes")
    if not 36 <= encoded[0] <= 45 or not 0 <= encoded[21] <= 9:
        raise ValueError("encoded body SN has invalid boundary digits")
    if any(value > 63 for value in encoded[1:21]):
        raise ValueError("encoded body SN contains an out-of-domain substitution byte")
    inverse_s1 = [0] * 64
    inverse_s2 = [0] * 64
    for index, value in enumerate(S1):
        inverse_s1[value] = index
    for index, value in enumerate(S2):
        inverse_s2[value] = index

    key = min(encoded[21], 9)
    values = [0] * 22
    values[0] = encoded[0] - 36
    values[21] = encoded[21]
    for index in range(20):
        encoded_index = 1 + P[key][index]
        values[index + 1] = inverse_s1[inverse_s2[encoded[encoded_index]]]
    if any(value < 0 or value > 9 for value in values):
        raise ValueError("encoded bytes do not decode to a 22-digit body SN")
    return "".join(str(value) for value in values)


def _crc8_table() -> tuple[int, ...]:
    table: list[int] = []
    for input_byte in range(256):
        remainder = 0
        value = input_byte
        for _ in range(8):
            if ((value ^ remainder) & 1) == 1:
                remainder = ((remainder ^ 0x18) >> 1) | 0x80
            else:
                remainder >>= 1
            value >>= 1
        table.append(remainder & 0xFF)
    return tuple(table)


CRC8_TABLE = _crc8_table()


def crc8(data: bytes | bytearray, offset: int, length: int) -> int:
    seed = 0
    for value in data[offset : offset + length]:
        seed = CRC8_TABLE[(seed ^ value) & 0xFF]
    return seed & 0xFF


def twos_complement_checksum(data: bytes | bytearray, start: int, end_exclusive: int) -> int:
    return (-sum(data[start:end_exclusive])) & 0xFF


def build_inner(sn: str, *, write: bool, counter: int) -> bytes:
    validate_body_sn(sn)
    if not 0 <= counter <= 255:
        raise ValueError("counter must fit in one byte")
    body = bytearray(37)
    body[0:3] = bytes((0xAA, 36, 0xAC))
    body[3:11] = bytes((0, 0, 0, 0, 0, 1, 0x0F, 0x80))
    body[11] = 0x41 if write else 0x40
    if write:
        body[12:34] = encode_sn(sn)
    body[34] = counter
    body[35] = crc8(body, 10, 25)
    body[36] = twos_complement_checksum(body, 1, 36)
    return bytes(body)


def _pkcs7_pad(data: bytes) -> bytes:
    amount = 16 - (len(data) % 16)
    return data + bytes((amount,)) * amount


def _pkcs7_unpad(data: bytes) -> bytes:
    if not data or len(data) % 16:
        raise ValueError("invalid padded AES data")
    amount = data[-1]
    if amount < 1 or amount > 16 or data[-amount:] != bytes((amount,)) * amount:
        raise ValueError("invalid PKCS7 padding")
    return data[:-amount]


def _powershell_aes(data: bytes, *, encrypt: bool) -> bytes:
    script = r"""
$data=[Convert]::FromBase64String($env:MIDEA_AES_DATA)
$key=[Text.Encoding]::UTF8.GetBytes('d4d5jljeiasdrc33')
$aes=[Security.Cryptography.Aes]::Create()
$aes.Mode=[Security.Cryptography.CipherMode]::ECB
$aes.Padding=[Security.Cryptography.PaddingMode]::PKCS7
$aes.Key=$key
$transform=if($env:MIDEA_AES_MODE -eq 'encrypt'){$aes.CreateEncryptor()}else{$aes.CreateDecryptor()}
try{$result=$transform.TransformFinalBlock($data,0,$data.Length);[Convert]::ToBase64String($result)}
finally{$transform.Dispose();$aes.Dispose()}
"""
    environment = os.environ.copy()
    environment["MIDEA_AES_DATA"] = base64.b64encode(data).decode("ascii")
    environment["MIDEA_AES_MODE"] = "encrypt" if encrypt else "decrypt"
    completed = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
        check=True,
        capture_output=True,
        text=True,
        env=environment,
    )
    return base64.b64decode(completed.stdout.strip())


def aes_ecb_encrypt_pkcs7(data: bytes) -> bytes:
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

        encryptor = Cipher(algorithms.AES(AES_KEY), modes.ECB()).encryptor()
        return encryptor.update(_pkcs7_pad(data)) + encryptor.finalize()
    except ImportError:
        return _powershell_aes(data, encrypt=True)


def aes_ecb_decrypt_pkcs7(data: bytes) -> bytes:
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

        decryptor = Cipher(algorithms.AES(AES_KEY), modes.ECB()).decryptor()
        return _pkcs7_unpad(decryptor.update(data) + decryptor.finalize())
    except ImportError:
        return _powershell_aes(data, encrypt=False)


def build_transport(inner: bytes, message_id: int) -> bytes:
    if not 0 <= message_id <= 0xFFFFFFFF:
        raise ValueError("message ID must fit in uint32")
    cipher = aes_ecb_encrypt_pkcs7(inner)
    total_length = 4 + 2 + 2 + 4 + 28 + len(cipher) + 16
    packet = bytearray(total_length)
    packet[0:4] = bytes((0x5A, 0x5A, 0x01, 0x00))
    packet[4:6] = struct.pack("<H", total_length)
    packet[6:8] = struct.pack("<H", 0x20)
    packet[8:12] = struct.pack("<I", message_id)
    packet[40 : 40 + len(cipher)] = cipher
    return bytes(packet)


def target_vectors(sn: str) -> dict[str, str]:
    encoded = encode_sn(sn)
    write_inner = build_inner(sn, write=True, counter=1)
    write_cipher = aes_ecb_encrypt_pkcs7(write_inner)
    query1_inner = build_inner(sn, write=False, counter=1)
    query1_cipher = aes_ecb_encrypt_pkcs7(query1_inner)
    query2_inner = build_inner(sn, write=False, counter=2)
    query2_cipher = aes_ecb_encrypt_pkcs7(query2_inner)
    return {
        "encoded": hex_bytes(encoded),
        "write_inner": hex_bytes(write_inner),
        "write_cipher": hex_bytes(write_cipher),
        "query1_inner": hex_bytes(query1_inner),
        "query1_cipher": hex_bytes(query1_cipher),
        "query2_inner": hex_bytes(query2_inner),
        "query2_cipher": hex_bytes(query2_cipher),
    }


def self_test() -> None:
    if sorted(S1) != list(range(64)) or sorted(S2) != list(range(64)):
        raise AssertionError("SN substitution table is not a 0..63 permutation")
    for row in P:
        if sorted(row) != list(range(20)):
            raise AssertionError("SN position table is not a 0..19 permutation")
    for sn, expected in ENCODING_VECTORS.items():
        encoded = encode_sn(sn)
        if hex_bytes(encoded) != expected:
            raise AssertionError(f"SN encoding vector failed for {sn}")
        if decode_sn(encoded) != sn:
            raise AssertionError(f"SN decoding round trip failed for {sn}")
    invalid_encoded_values = (
        bytes(22),
        bytes((36, *([0x40] * 20), 0)),
        bytes((46, *([0x11] * 20), 0)),
        bytes((36, *([0x11] * 20), 10)),
    )
    for invalid_encoded in invalid_encoded_values:
        try:
            decode_sn(invalid_encoded)
        except ValueError:
            pass
        else:
            raise AssertionError("invalid encoded body SN was accepted")
    known_inner = build_inner("1234567890123456789012", write=True, counter=1)
    if hex_bytes(known_inner) != KNOWN_WRITE_INNER:
        raise AssertionError("known write-inner vector failed")
    known_cipher = aes_ecb_encrypt_pkcs7(known_inner)
    if hex_bytes(known_cipher) != KNOWN_WRITE_CIPHER:
        raise AssertionError("known AES vector failed")
    if aes_ecb_decrypt_pkcs7(known_cipher) != known_inner:
        raise AssertionError("AES round trip failed")
    if len(build_transport(known_inner, 0)) != 104:
        raise AssertionError("transport length vector failed")

    corpus_path = Path(__file__).with_name("test_vectors.json")
    if not corpus_path.is_file():
        raise AssertionError("test_vectors.json is missing")
    corpus = json.loads(corpus_path.read_text(encoding="utf-8"))
    if corpus.get("schema_version") != 1:
        raise AssertionError("unsupported test-vector schema")
    for vector in corpus.get("encoding_vectors", []):
        body_sn = vector["body_sn"]
        encoded = encode_sn(body_sn)
        if hex_bytes(encoded) != vector["encoded_hex"] or decode_sn(encoded) != body_sn:
            raise AssertionError(f"external encoding vector failed for {body_sn}")
    for invalid in corpus.get("invalid_body_sn_inputs", []):
        try:
            validate_body_sn(invalid["value"])
        except ValueError:
            pass
        else:
            raise AssertionError(f"invalid body SN was accepted: {invalid['reason']}")
    frame = corpus.get("known_frame_vector", {})
    frame_sn = frame.get("body_sn")
    if hex_bytes(build_inner(frame_sn, write=True, counter=frame.get("counter"))) != frame.get("write_inner_hex"):
        raise AssertionError("external write-inner vector failed")
    if hex_bytes(aes_ecb_encrypt_pkcs7(build_inner(frame_sn, write=True, counter=frame.get("counter")))) != frame.get("write_cipher_hex"):
        raise AssertionError("external write-cipher vector failed")
    if len(build_transport(build_inner(frame_sn, write=True, counter=frame.get("counter")), 0)) != frame.get("transport_length"):
        raise AssertionError("external transport-length vector failed")
    for vector in corpus.get("counter_vectors", []):
        inner = build_inner(
            vector["body_sn"],
            write=vector["operation"] == "write",
            counter=vector["counter"],
        )
        if hex_bytes(inner) != vector["inner_hex"] or hex_bytes(aes_ecb_encrypt_pkcs7(inner)) != vector["cipher_hex"]:
            raise AssertionError(f"external counter vector failed for counter {vector['counter']}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Offline regression self-test for the verified 22-digit Midea body-SN protocol. "
            "Target-specific vectors are available only to the evidence-gated package generator, not this CLI."
        )
    )
    parser.add_argument("--self-test", action="store_true", help="run the bundled immutable regression corpus")
    parser.parse_args()
    self_test()
    print("protocol_reference self-test: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
