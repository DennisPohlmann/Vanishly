import json
import pathlib
import unittest

from vanishly import DecryptError, decrypt_secret, encrypt_secret, unlock_key, verifier_for
from vanishly.client import parse_link
from vanishly.crypto import from_b64url, to_b64url

VECTORS = json.loads((pathlib.Path(__file__).resolve().parents[2] / "testvectors.json").read_text("utf-8"))["vectors"]


class Vectors(unittest.TestCase):
    def test_encrypt_matches_javascript(self):
        for v in VECTORS:
            with self.subTest(v["name"]):
                key, payload = encrypt_secret(v["plaintext"], v["passphrase"], iterations=v["iterations"],
                                              _key=from_b64url(v["key"]), _salt=from_b64url(v["salt"]), _iv=from_b64url(v["iv"]))
                self.assertEqual(key, v["key"])
                self.assertEqual(payload["ciphertext"], v["ciphertext"])
                self.assertEqual(payload.get("verifier"), v["verifier"])

    def test_decrypt_javascript_vectors(self):
        for v in VECTORS:
            with self.subTest(v["name"]):
                pk = unlock_key(v["passphrase"], v["salt"], v["iterations"]) if v["passphrase"] else b""
                if v["passphrase"]:
                    self.assertEqual(verifier_for(pk, v["salt"]), v["verifier"])
                self.assertEqual(decrypt_secret(v, v["key"], pk), v["plaintext"])

    def test_wrong_key_or_passphrase_or_tampering(self):
        v = next(x for x in VECTORS if x["passphrase"])
        pk = unlock_key(v["passphrase"], v["salt"], v["iterations"])
        with self.assertRaises(DecryptError):
            decrypt_secret(v, v["key"])  # passphrase missing
        with self.assertRaises(DecryptError):
            decrypt_secret(v, "A" * 43, pk)
        ct = bytearray(from_b64url(v["ciphertext"]))
        ct[0] ^= 1
        with self.assertRaises(DecryptError):
            decrypt_secret({**v, "ciphertext": to_b64url(bytes(ct))}, v["key"], pk)

    def test_round_trip_random(self):
        key, payload = encrypt_secret("hällo 🔐", "pw")
        self.assertEqual(len(key), 43)
        self.assertEqual(payload["iterations"], 600000)
        pk = unlock_key("pw", payload["salt"], payload["iterations"])
        self.assertEqual(decrypt_secret(payload, key, pk), "hällo 🔐")

    def test_parse_link(self):
        sid, key = "A" * 22, "b" * 43
        self.assertEqual(parse_link(f"https://x.example/s/{sid}#{key}"), ("https://x.example", sid, key))
        self.assertEqual(parse_link(f"https://x.example/ots/s/{sid}#{key}")[0], "https://x.example/ots")
        for bad in ("https://x.example/s/short#key", f"ftp://x/s/{sid}#{key}", f"https://x/s/{sid}"):
            with self.assertRaises(ValueError):
                parse_link(bad)

    def test_base64url(self):
        for n in range(40):
            self.assertEqual(from_b64url(to_b64url(bytes(range(n)))), bytes(range(n)))
        for bad in ("a+b/", "abcde", "a=="):
            with self.assertRaises(ValueError):
                from_b64url(bad)


if __name__ == "__main__":
    unittest.main()
