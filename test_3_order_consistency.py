import json
import os
import shutil
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
    BUNDLE_TYPE,
    SCHEMA_VERSION,
    TEST_SCOPE,
    build_parity_manifest,
    verify_audit_file,
    verify_merkle_batch_audit,
    verify_standard_envelope_audit,
    verify_unified_bundle,
)


BUNDLE_PATH = Path("applied_evidence_bundle.json")
WORKSPACE_NAME = ".tmp_workspace"


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
            "test_scope": TEST_SCOPE,
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
        "schema_version": SCHEMA_VERSION,
        "test_scope": TEST_SCOPE,
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


def build_unified_bundle(
    standard_package: Dict[str, Any],
    merkle_package: Dict[str, Any],
) -> Dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "test_scope": TEST_SCOPE,
        "bundle_type": BUNDLE_TYPE,
        "standard_audit": standard_package,
        "merkle_audit": merkle_package,
        "parity_manifest": build_parity_manifest(
            standard_package, merkle_package
        ),
    }


def _clean_workspace(workspace: Path) -> None:
    if workspace.is_symlink():
        raise RuntimeError("Refusing to use a symlinked temporary workspace")
    if workspace.exists():
        if not workspace.is_dir():
            raise RuntimeError("Temporary workspace path is not a directory")
        shutil.rmtree(workspace)


def _fsync_directory(directory: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    try:
        descriptor = os.open(directory, flags)
    except OSError:
        return
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def write_verified_bundle(
    bundle: Dict[str, Any], output_path: Path = BUNDLE_PATH
) -> None:
    """Verify in memory and on disk before one atomic final replacement."""
    if not verify_unified_bundle(bundle):
        raise RuntimeError("Unified bundle verification failed before writing")

    output_path = Path(output_path)
    output_directory = output_path.parent.resolve()
    output_directory.mkdir(parents=True, exist_ok=True)
    workspace = output_directory / WORKSPACE_NAME
    _clean_workspace(workspace)
    workspace.mkdir()
    temporary_bundle = workspace / output_path.name

    try:
        with temporary_bundle.open(
            "w", encoding="utf-8", newline="\n"
        ) as file_handle:
            json.dump(
                bundle,
                file_handle,
                indent=2,
                ensure_ascii=False,
                allow_nan=False,
            )
            file_handle.write("\n")
            file_handle.flush()
            os.fsync(file_handle.fileno())

        if not verify_audit_file(str(temporary_bundle)):
            raise RuntimeError("Unified bundle verification failed on disk")

        os.replace(temporary_bundle, output_path)
        _fsync_directory(output_directory)
    finally:
        if workspace.exists() and not workspace.is_symlink():
            shutil.rmtree(workspace)


def main() -> None:
    standard_package, merkle_package = run_3_order_consistency_test()
    if not verify_standard_envelope_audit(standard_package):
        raise RuntimeError("Standard envelope verification failed")
    if not verify_merkle_batch_audit(merkle_package):
        raise RuntimeError("Merkle batch verification failed")
    bundle = build_unified_bundle(standard_package, merkle_package)
    write_verified_bundle(bundle)
    print("UNIFIED BUNDLE VERIFICATION PASSED")


if __name__ == "__main__":
    main()
