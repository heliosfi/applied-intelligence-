import base64
import hashlib
import hmac
import json
import re
import secrets
from typing import Any, Dict, Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


QUANTITY_PATTERN = re.compile(r"^[1-9][0-9]*$")
PRICE_PATTERN = re.compile(r"^(?:0|[1-9][0-9]*)\.[0-9]{2}$")


def canonical_json_bytes(data: Any) -> bytes:
    """Serialize supported JSON data using the package's canonical profile."""
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def compute_canonical_hash(data: Dict[str, Any]) -> str:
    """Compute SHA-256 over the canonical JSON representation."""
    return hashlib.sha256(canonical_json_bytes(data)).hexdigest()


class OrderStateMachine:
    """Enforce scheduled -> dispatched -> in_progress -> completed."""

    VALID_TRANSITIONS = {
        "scheduled": "dispatched",
        "dispatched": "in_progress",
        "in_progress": "completed",
    }

    def __init__(
        self, order_id: str, symbol: str, quantity: str, price: str
    ) -> None:
        if not isinstance(order_id, str) or not order_id:
            raise ValueError("order_id must be a non-empty string")
        if not isinstance(symbol, str) or not symbol:
            raise ValueError("symbol must be a non-empty string")
        if not isinstance(quantity, str) or not QUANTITY_PATTERN.fullmatch(quantity):
            raise ValueError("quantity must be a positive canonical integer string")
        if not isinstance(price, str) or not PRICE_PATTERN.fullmatch(price):
            raise ValueError("price must be a canonical non-negative 2-decimal string")

        self.order_id = order_id
        self.symbol = symbol
        self.quantity = quantity
        self.price = price
        self.current_state = "scheduled"
        self.history = [self.current_state]

    def transition_to(self, next_state: str) -> None:
        expected = self.VALID_TRANSITIONS.get(self.current_state)
        if next_state != expected:
            raise ValueError(
                f"Illegal state transition from '{self.current_state}' "
                f"to '{next_state}'. Expected '{expected}'."
            )
        self.current_state = next_state
        self.history.append(self.current_state)

    def execute_lifecycle(self) -> Dict[str, Any]:
        self.transition_to("dispatched")
        self.transition_to("in_progress")
        self.transition_to("completed")
        return {
            "order_id": self.order_id,
            "symbol": self.symbol,
            "quantity": self.quantity,
            "price": self.price,
            "final_state": self.current_state,
            "state_history": list(self.history),
        }


class CryptographicSigner:
    """Provide local RSA-PSS and HMAC-SHA256 signing primitives."""

    def __init__(
        self,
        private_key_pem: Optional[str] = None,
        hmac_secret_key: Optional[bytes] = None,
        allow_ephemeral_keys: bool = False,
    ) -> None:
        # Fail closed: ephemeral key generation is permitted only under an
        # explicit development/test allowance. Production execution must not
        # silently mint signing identity when material is missing.
        if private_key_pem is None and not allow_ephemeral_keys:
            raise ValueError(
                "No RSA signing material provided: pass private_key_pem or "
                "set allow_ephemeral_keys=True for explicit development/test "
                "use. Refusing to generate ephemeral production keys."
            )
        if private_key_pem is None:
            private_key = rsa.generate_private_key(
                public_exponent=65537, key_size=2048
            )
        else:
            loaded_key = serialization.load_pem_private_key(
                private_key_pem.encode("utf-8"), password=None
            )
            if not isinstance(loaded_key, rsa.RSAPrivateKey):
                raise TypeError("private_key_pem must contain an RSA private key")
            private_key = loaded_key

        if private_key.key_size < 2048:
            raise ValueError("RSA keys smaller than 2048 bits are not supported")
        if hmac_secret_key is not None and not isinstance(hmac_secret_key, bytes):
            raise TypeError("hmac_secret_key must be bytes")
        if hmac_secret_key is not None and len(hmac_secret_key) < 32:
            raise ValueError("hmac_secret_key must contain at least 32 bytes")

        self._private_key = private_key
        self.public_key = private_key.public_key()
        self._hmac_secret_key = hmac_secret_key or secrets.token_bytes(32)

    def sign_rsa(self, data_bytes: bytes) -> str:
        if not isinstance(data_bytes, bytes):
            raise TypeError("data_bytes must be bytes")
        signature = self._private_key.sign(
            data_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return base64.b64encode(signature).decode("ascii")

    def sign_hmac(self, data_bytes: bytes) -> str:
        if not isinstance(data_bytes, bytes):
            raise TypeError("data_bytes must be bytes")
        return hmac.new(
            self._hmac_secret_key, data_bytes, hashlib.sha256
        ).hexdigest()

    def verify_hmac(self, data_bytes: bytes, signature_hex: str) -> bool:
        expected = self.sign_hmac(data_bytes)
        return hmac.compare_digest(expected, signature_hex)

    def export_public_key_pem(self) -> str:
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")
