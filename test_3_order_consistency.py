import json
import os
from pathlib import Path
from typing import Any, Dict, List, Tuple

from merkle_batch_signer import MerkleBatchSigner
from signed_audit_suite import (
    CryptographicSigner,
    OrderStateMachine,
    canonical_json_bytes,
    compute_canonical_hash,
)
from verify_audit_log import (
    verify_merkle_batch_audit,
    verify_standard_envelope_audit,
)


ARTIFACT_PATHS = (
    Path("order_execution_audit.json"),
    Path("merkle_batch_audit.json"),
)


def purge_stale_artifacts() -> None:
    """Remove only the bounded evidence outputs and their temporary files."""
    for path in ARTIFACT_PATHS:
        path.unlink(missing_ok=True)
        path.with_suffix(path.suffix + ".tmp").unlink(missing_ok=True)


def _write_json_temp(path: Path, data: Dict[str, Any]) -> Path:
    temp_path = path.with_suffix(path.suffix + ".tmp")
    with temp_path.open("w", encoding="utf-8", newline="\n") as file_handle:
        json.dump(
            data,
            file_handle,
            indent=2,
            ensure_ascii=False,
            allow_nan=False,
        )
        file_handle.write("\n")
        file_handle.flush()
        os.fsync(file_handle.fileno())
    return temp_path


def write_evidence_pair(
    standard_package: Dict[str, Any],
    merkle_package: Dict[str, Any],
) -> None:
    """Prepare both files before replacing either bounded final path."""
    temp_paths: List[Path] = []
    try:
        temp_paths.append(_write_json_temp(ARTIFACT_PATHS[0], standard_package))
        temp_paths.append(_write_json_temp(ARTIFACT_PATHS[1], merkle_package))
        for temp_path, final_path in zip(temp_paths, ARTIFACT_PATHS):
            os.replace(temp_path, final_path)
    finally:
        for temp_path in temp_paths:
            temp_path.unlink(missing_ok=True)


def run_3_order_consistency_test() -> Tuple[Dict[str, Any], Dict[str, Any]]:
    signer = CryptographicSigner()
    orders_data = [
        {
            "id": "ORD-001",
            "symbol": "HELIOS-USD",
            "qty": "100",
            "price": "150.00",
        },
        {
            "id": "ORD-002",
            "symbol": "SELENE-ETH",
            "qty": "10",
            "price": "2800.00",
        },
        {
            "id": "ORD-003",
            "symbol": "AETHER-BTC",
            "qty": "1",
            "price": "65000.00",
        },
    ]
    executed_payloads: List[Dict[str, Any]] = []
    standard_envelopes: List[Dict[str, Any]] = []

    for order_info in orders_data:
        lifecycle = OrderStateMachine(
            order_info["id"],
            order_info["symbol"],
            order_info["qty"],
            order_info["price"],
        ).execute_lifecycle()
        payload = {
            "order_id": order_info["id"],
            "test_scope": "3_order_local_fixture",
            "lifecycle": lifecycle,
            "canonical_hash": compute_canonical_hash(lifecycle),
        }
        executed_payloads.append(payload)
        standard_envelopes.append(
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
        "total_executed": len(standard_envelopes),
        "public_key_pem": signer.export_public_key_pem(),
        "execution_envelopes": standard_envelopes,
    }
    standard_package = {
        "report": report,
        "container_signatures": {
            "rsa_pss_sha256": signer.sign_rsa(canonical_json_bytes(report))
        },
    }
    merkle_package = MerkleBatchSigner(signer).sign_batch(executed_payloads)

    standard_payloads = [
        envelope["payload"] for envelope in report["execution_envelopes"]
    ]
    merkle_payloads = [
        envelope["payload"] for envelope in merkle_package["envelopes"]
    ]
    if standard_payloads != executed_payloads:
        raise RuntimeError("Standard payloads do not match executed payloads")
    if merkle_payloads != executed_payloads:
        raise RuntimeError("Merkle payloads do not match executed payloads")
    for index, payload in enumerate(executed_payloads):
        expected_hash = compute_canonical_hash(payload["lifecycle"])
        if payload["canonical_hash"] != expected_hash:
            raise RuntimeError(f"Canonical hash mismatch at index {index}")

    return standard_package, merkle_package


def main() -> None:
    purge_stale_artifacts()
    standard_package, merkle_package = run_3_order_consistency_test()
    if not verify_standard_envelope_audit(standard_package):
        raise RuntimeError("Standard envelope verification failed")
    if not verify_merkle_batch_audit(merkle_package):
        raise RuntimeError("Merkle batch verification failed")
    write_evidence_pair(standard_package, merkle_package)
    print("ALL TESTS & PARITY CHECKS PASSED SUCCESSFULLY.")


if __name__ == "__main__":
    main()
