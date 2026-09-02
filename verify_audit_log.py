import base64
import binascii
import json
from pathlib import Path
from typing import Any, Dict, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from merkle_batch_signer import MerkleTree, verify_merkle_proof
from signed_audit_suite import canonical_json_bytes, compute_canonical_hash


SCHEMA_VERSION = "1.0.0"
TEST_SCOPE = "3_order_local_fixture"
EXPECTED_ITEM_COUNT = 3
EXPECTED_HISTORY = ["scheduled", "dispatched", "in_progress", "completed"]


def load_public_key_from_pem(pem_str: str) -> rsa.RSAPublicKey:
    loaded_key = serialization.load_pem_public_key(pem_str.encode("utf-8"))
    if not isinstance(loaded_key, rsa.RSAPublicKey):
        raise TypeError("PEM does not contain an RSA public key")
    if loaded_key.key_size < 2048:
        raise ValueError("RSA public key must be at least 2048 bits")
    return loaded_key


def verify_rsa_signature(
    public_key: rsa.RSAPublicKey, data_bytes: bytes, signature_b64: str
) -> bool:
    try:
        signature = base64.b64decode(signature_b64, validate=True)
        public_key.verify(
            signature,
            data_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except (InvalidSignature, ValueError, TypeError, binascii.Error):
        return False


def _valid_payload(payload: Any) -> bool:
    if not isinstance(payload, dict):
        return False
    if set(payload) != {"order_id", "test_scope", "lifecycle", "canonical_hash"}:
        return False
    if payload["test_scope"] != TEST_SCOPE:
        return False
    lifecycle = payload["lifecycle"]
    if not isinstance(lifecycle, dict):
        return False
    if set(lifecycle) != {
        "order_id",
        "symbol",
        "quantity",
        "price",
        "final_state",
        "state_history",
    }:
        return False
    if lifecycle["order_id"] != payload["order_id"]:
        return False
    if lifecycle["final_state"] != "completed":
        return False
    if lifecycle["state_history"] != EXPECTED_HISTORY:
        return False
    if compute_canonical_hash(lifecycle) != payload["canonical_hash"]:
        return False
    return True


def _unique_order_ids(envelopes: list[Dict[str, Any]]) -> bool:
    try:
        order_ids = [env["payload"]["order_id"] for env in envelopes]
    except (KeyError, TypeError):
        return False
    return len(order_ids) == len(set(order_ids))


def verify_merkle_batch_audit(audit_package: Dict[str, Any]) -> bool:
    try:
        if set(audit_package) != {
            "schema_version",
            "test_scope",
            "batch_metadata",
            "envelopes",
        }:
            return False
        if audit_package["schema_version"] != SCHEMA_VERSION:
            return False
        if audit_package["test_scope"] != TEST_SCOPE:
            return False

        metadata = audit_package["batch_metadata"]
        envelopes = audit_package["envelopes"]
        if not isinstance(metadata, dict) or not isinstance(envelopes, list):
            return False
        if set(metadata) != {
            "total_items",
            "merkle_root",
            "public_key_pem",
            "batch_rsa_pss_signature",
        }:
            return False
        if metadata["total_items"] != EXPECTED_ITEM_COUNT:
            return False
        if len(envelopes) != metadata["total_items"]:
            return False
        if not _unique_order_ids(envelopes):
            return False
        if [env.get("leaf_index") for env in envelopes] != list(
            range(metadata["total_items"])
        ):
            return False

        merkle_root = metadata["merkle_root"]
        if not isinstance(merkle_root, str) or len(bytes.fromhex(merkle_root)) != 32:
            return False
        public_key = load_public_key_from_pem(metadata["public_key_pem"])
        if not verify_rsa_signature(
            public_key,
            bytes.fromhex(merkle_root),
            metadata["batch_rsa_pss_signature"],
        ):
            return False

        for envelope in envelopes:
            if set(envelope) != {
                "leaf_index",
                "payload",
                "leaf_hash",
                "merkle_proof",
            }:
                return False
            payload = envelope["payload"]
            if not _valid_payload(payload):
                return False
            leaf_hash = envelope["leaf_hash"]
            if MerkleTree._hash_payload(payload) != leaf_hash:
                return False
            if not verify_merkle_proof(
                leaf_hash, envelope["merkle_proof"], merkle_root
            ):
                return False
        return True
    except (
        KeyError,
        TypeError,
        ValueError,
        UnicodeError,
        binascii.Error,
    ):
        return False


def verify_standard_envelope_audit(audit_package: Dict[str, Any]) -> bool:
    try:
        if set(audit_package) != {"report", "container_signatures"}:
            return False
        report = audit_package["report"]
        container_signatures = audit_package["container_signatures"]
        if not isinstance(report, dict) or set(report) != {
            "schema_version",
            "test_scope",
            "total_executed",
            "public_key_pem",
            "execution_envelopes",
        }:
            return False
        if report["schema_version"] != SCHEMA_VERSION:
            return False
        if report["test_scope"] != TEST_SCOPE:
            return False
        envelopes = report["execution_envelopes"]
        if not isinstance(envelopes, list):
            return False
        if report["total_executed"] != EXPECTED_ITEM_COUNT:
            return False
        if len(envelopes) != report["total_executed"]:
            return False
        if not _unique_order_ids(envelopes):
            return False
        if set(container_signatures) != {"rsa_pss_sha256"}:
            return False

        public_key = load_public_key_from_pem(report["public_key_pem"])
        if not verify_rsa_signature(
            public_key,
            canonical_json_bytes(report),
            container_signatures["rsa_pss_sha256"],
        ):
            return False

        for envelope in envelopes:
            if set(envelope) != {"payload", "signatures"}:
                return False
            payload = envelope["payload"]
            signatures = envelope["signatures"]
            if not _valid_payload(payload):
                return False
            if not isinstance(signatures, dict) or set(signatures) != {
                "rsa_pss_sha256"
            }:
                return False
            if not verify_rsa_signature(
                public_key,
                canonical_json_bytes(payload),
                signatures["rsa_pss_sha256"],
            ):
                return False
        return True
    except (
        KeyError,
        TypeError,
        ValueError,
        UnicodeError,
        binascii.Error,
    ):
        return False


def verify_audit_file(file_path: str) -> bool:
    try:
        with Path(file_path).open("r", encoding="utf-8") as file_handle:
            audit_package = json.load(file_handle)
    except (OSError, UnicodeError, json.JSONDecodeError):
        return False
    if not isinstance(audit_package, dict):
        return False

    is_standard = set(audit_package) == {"report", "container_signatures"}
    is_merkle = set(audit_package) == {
        "schema_version",
        "test_scope",
        "batch_metadata",
        "envelopes",
    }
    if is_standard == is_merkle:
        return False
    if is_standard:
        return verify_standard_envelope_audit(audit_package)
    return verify_merkle_batch_audit(audit_package)
