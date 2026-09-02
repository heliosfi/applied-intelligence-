import hashlib
from typing import Any, Dict, List

from signed_audit_suite import CryptographicSigner, canonical_json_bytes


class MerkleTree:
    """Binary Merkle tree with domain-separated leaf and parent hashing."""

    def __init__(self, raw_items: List[Dict[str, Any]]) -> None:
        if not raw_items:
            raise ValueError("Cannot construct an empty Merkle tree")
        self.raw_items = list(raw_items)
        self.leaf_hashes = [self._hash_payload(item) for item in raw_items]
        self.tree_levels: List[List[str]] = [list(self.leaf_hashes)]
        self._build_tree()

    @staticmethod
    def _hash_payload(payload: Dict[str, Any]) -> str:
        return hashlib.sha256(b"\x00" + canonical_json_bytes(payload)).hexdigest()

    @staticmethod
    def combine_hashes(left: str, right: str) -> str:
        try:
            left_bytes = bytes.fromhex(left)
            right_bytes = bytes.fromhex(right)
        except ValueError as exc:
            raise ValueError("Merkle node hashes must be hexadecimal") from exc
        if len(left_bytes) != 32 or len(right_bytes) != 32:
            raise ValueError("Merkle node hashes must be SHA-256 digests")
        return hashlib.sha256(b"\x01" + left_bytes + right_bytes).hexdigest()

    def _build_tree(self) -> None:
        current_level = list(self.leaf_hashes)
        while len(current_level) > 1:
            working_level = list(current_level)
            if len(working_level) % 2:
                working_level.append(working_level[-1])
            next_level = [
                self.combine_hashes(working_level[i], working_level[i + 1])
                for i in range(0, len(working_level), 2)
            ]
            self.tree_levels.append(next_level)
            current_level = next_level

    @property
    def root_hash(self) -> str:
        return self.tree_levels[-1][0]

    def get_proof(self, index: int) -> List[Dict[str, str]]:
        if index < 0 or index >= len(self.leaf_hashes):
            raise IndexError("Merkle proof index is out of bounds")

        proof: List[Dict[str, str]] = []
        current_index = index
        for level in self.tree_levels[:-1]:
            working_level = list(level)
            if len(working_level) % 2:
                working_level.append(working_level[-1])
            is_right_child = current_index % 2 == 1
            sibling_index = current_index - 1 if is_right_child else current_index + 1
            proof.append(
                {
                    "position": "left" if is_right_child else "right",
                    "hash": working_level[sibling_index],
                }
            )
            current_index //= 2
        return proof


class MerkleBatchSigner:
    """Sign a Merkle root and emit an indexed proof for every payload."""

    def __init__(self, signer: CryptographicSigner) -> None:
        self.signer = signer

    def sign_batch(self, payload_list: List[Dict[str, Any]]) -> Dict[str, Any]:
        if not payload_list:
            raise ValueError("Cannot batch-sign an empty payload list")

        tree = MerkleTree(payload_list)
        envelopes = [
            {
                "leaf_index": index,
                "payload": payload,
                "leaf_hash": tree.leaf_hashes[index],
                "merkle_proof": tree.get_proof(index),
            }
            for index, payload in enumerate(payload_list)
        ]
        return {
            "schema_version": "1.0.0",
            "test_scope": "3_order_local_fixture",
            "batch_metadata": {
                "total_items": len(payload_list),
                "merkle_root": tree.root_hash,
                "public_key_pem": self.signer.export_public_key_pem(),
                "batch_rsa_pss_signature": self.signer.sign_rsa(
                    bytes.fromhex(tree.root_hash)
                ),
            },
            "envelopes": envelopes,
        }


def verify_merkle_proof(
    leaf_hash: str, proof: List[Dict[str, str]], expected_root: str
) -> bool:
    try:
        current_hash = leaf_hash
        for node in proof:
            if set(node) != {"position", "hash"}:
                return False
            position = node["position"]
            sibling_hash = node["hash"]
            if position == "left":
                current_hash = MerkleTree.combine_hashes(
                    sibling_hash, current_hash
                )
            elif position == "right":
                current_hash = MerkleTree.combine_hashes(
                    current_hash, sibling_hash
                )
            else:
                return False
        return current_hash == expected_root
    except (TypeError, ValueError):
        return False
