import copy
import json
import tempfile
import unittest
from pathlib import Path

from signed_audit_suite import (
    CryptographicSigner,
    OrderStateMachine,
    canonical_json_bytes,
)
from test_3_order_consistency import run_3_order_consistency_test
from verify_audit_log import (
    verify_audit_file,
    verify_merkle_batch_audit,
    verify_rsa_signature,
    verify_standard_envelope_audit,
)


class AppliedEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.standard, cls.merkle = run_3_order_consistency_test()

    def test_illegal_state_transition_is_rejected(self) -> None:
        state_machine = OrderStateMachine(
            "ORD-ERR", "HELIOS-USD", "10", "100.00"
        )
        with self.assertRaises(ValueError):
            state_machine.transition_to("completed")

    def test_noncanonical_numeric_values_are_rejected(self) -> None:
        invalid_values = [
            ("10.0", "100.00"),
            ("01", "100.00"),
            ("10", "100"),
            ("10", "0100.00"),
        ]
        for quantity, price in invalid_values:
            with self.subTest(quantity=quantity, price=price):
                with self.assertRaises(ValueError):
                    OrderStateMachine(
                        "ORD-ERR", "HELIOS-USD", quantity, price
                    )
        with self.assertRaises(ValueError):
            OrderStateMachine("ORD-ERR", "HELIOS-USD", 10, "100.00")

    def test_tampered_rsa_payload_is_rejected(self) -> None:
        signer = CryptographicSigner()
        signature = signer.sign_rsa(b"authentic_payload")
        self.assertFalse(
            verify_rsa_signature(
                signer.public_key, b"tampered_payload", signature
            )
        )

    def test_tampered_hmac_payload_is_rejected(self) -> None:
        signer = CryptographicSigner(hmac_secret_key=b"x" * 32)
        signature = signer.sign_hmac(b"authentic_payload")
        self.assertTrue(signer.verify_hmac(b"authentic_payload", signature))
        self.assertFalse(signer.verify_hmac(b"tampered_payload", signature))

    def test_standard_package_passes(self) -> None:
        self.assertTrue(verify_standard_envelope_audit(self.standard))

    def test_merkle_package_passes(self) -> None:
        self.assertTrue(verify_merkle_batch_audit(self.merkle))

    def test_incomplete_merkle_batch_is_rejected(self) -> None:
        incomplete = copy.deepcopy(self.merkle)
        incomplete["envelopes"] = []
        self.assertFalse(verify_merkle_batch_audit(incomplete))

    def test_merkle_proof_tampering_is_rejected(self) -> None:
        tampered = copy.deepcopy(self.merkle)
        tampered["envelopes"][0]["merkle_proof"][0]["hash"] = "00" * 32
        self.assertFalse(verify_merkle_batch_audit(tampered))

    def test_false_canonical_hash_is_rejected_even_when_signed(self) -> None:
        signer = CryptographicSigner()
        envelopes = []
        for index in range(3):
            lifecycle = OrderStateMachine(
                f"ORD-{index}", "HELIOS-USD", "1", "1.00"
            ).execute_lifecycle()
            payload = {
                "order_id": f"ORD-{index}",
                "test_scope": "3_order_local_fixture",
                "lifecycle": lifecycle,
                "canonical_hash": "00" * 32,
            }
            envelopes.append(
                {
                    "payload": payload,
                    "signatures": {
                        "rsa_pss_sha256": signer.sign_rsa(
                            canonical_json_bytes(payload)
                        )
                    },
                }
            )
        report = {
            "schema_version": "1.0.0",
            "test_scope": "3_order_local_fixture",
            "total_executed": 3,
            "public_key_pem": signer.export_public_key_pem(),
            "execution_envelopes": envelopes,
        }
        package = {
            "report": report,
            "container_signatures": {
                "rsa_pss_sha256": signer.sign_rsa(canonical_json_bytes(report))
            },
        }
        self.assertFalse(verify_standard_envelope_audit(package))

    def test_count_mismatch_is_rejected(self) -> None:
        mismatch = copy.deepcopy(self.standard)
        mismatch["report"]["total_executed"] = 2
        self.assertFalse(verify_standard_envelope_audit(mismatch))

    def test_ambiguous_schema_is_rejected(self) -> None:
        ambiguous = copy.deepcopy(self.standard)
        ambiguous["batch_metadata"] = {}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ambiguous.json"
            path.write_text(json.dumps(ambiguous), encoding="utf-8")
            self.assertFalse(verify_audit_file(str(path)))


if __name__ == "__main__":
    unittest.main(verbosity=2)
