import copy
import tempfile
import unittest
from pathlib import Path

from signed_audit_suite import (
    CryptographicSigner,
    OrderStateMachine,
    canonical_json_bytes,
)
from test_3_order_consistency import (
    WORKSPACE_NAME,
    build_unified_bundle,
    run_3_order_consistency_test,
    write_verified_bundle,
)
from verify_audit_log import (
    verify_audit_file,
    verify_merkle_batch_audit,
    verify_rsa_signature,
    verify_standard_envelope_audit,
    verify_unified_bundle,
)


class AppliedEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.standard, cls.merkle = run_3_order_consistency_test()
        cls.bundle = build_unified_bundle(cls.standard, cls.merkle)

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

    def test_unified_bundle_passes_in_memory_and_on_disk(self) -> None:
        self.assertTrue(verify_unified_bundle(self.bundle))
        with tempfile.TemporaryDirectory() as directory:
            output_path = Path(directory) / "applied_evidence_bundle.json"
            write_verified_bundle(self.bundle, output_path)
            self.assertTrue(verify_audit_file(str(output_path)))
            self.assertFalse((Path(directory) / WORKSPACE_NAME).exists())

    def test_mixed_key_bundle_is_rejected_and_canonical_file_preserved(
        self,
    ) -> None:
        _, second_merkle = run_3_order_consistency_test()
        mixed_bundle = build_unified_bundle(self.standard, second_merkle)
        self.assertFalse(verify_unified_bundle(mixed_bundle))

        with tempfile.TemporaryDirectory() as directory:
            output_path = Path(directory) / "applied_evidence_bundle.json"
            sentinel = b"preserved-canonical-evidence\n"
            output_path.write_bytes(sentinel)
            with self.assertRaises(RuntimeError):
                write_verified_bundle(mixed_bundle, output_path)
            self.assertEqual(output_path.read_bytes(), sentinel)
            self.assertFalse((Path(directory) / WORKSPACE_NAME).exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
