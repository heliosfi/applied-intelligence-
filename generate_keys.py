"""Generate an RSA signing key pair for local development and test use.

The private key is written in unencrypted PKCS8 PEM format, loadable by
``CryptographicSigner`` via its ``private_key_pem`` parameter. The public
key is written as SubjectPublicKeyInfo PEM.

This utility exists for development and test environments only. Generated
private keys must never be committed, logged, placed in build artifacts, or
exposed in CI output. For any real deployment, provision signing identity
through a secrets manager or KMS (e.g. GitHub Secrets, HashiCorp Vault) and
load it at runtime from the environment.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import stat
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


DEFAULT_KEY_SIZE = 2048
ALLOWED_KEY_SIZES = (2048, 3072, 4096)


def generate_keypair(key_size: int) -> rsa.RSAPrivateKey:
    """Generate an RSA private key of the requested size."""
    if key_size not in ALLOWED_KEY_SIZES:
        raise ValueError(
            f"key_size must be one of {ALLOWED_KEY_SIZES}; got {key_size}"
        )
    return rsa.generate_private_key(public_exponent=65537, key_size=key_size)


def public_key_fingerprint(private_key: rsa.RSAPrivateKey) -> str:
    """Return the SHA-256 fingerprint of the public key (hex)."""
    der = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(der).hexdigest()


def write_key_files(
    private_key: rsa.RSAPrivateKey,
    out_dir: Path,
    prefix: str,
    force: bool,
) -> tuple[Path, Path]:
    """Write private (0600) and public (0644) PEM files. Fail closed."""
    out_dir.mkdir(parents=True, exist_ok=True)

    private_path = out_dir / f"{prefix}_private.pem"
    public_path = out_dir / f"{prefix}_public.pem"

    for path in (private_path, public_path):
        if path.exists() and not force:
            raise FileExistsError(
                f"{path} already exists; refusing to overwrite "
                "(use --force to replace it explicitly)"
            )

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    # Private key first, owner-only, before any other file exists.
    fd = os.open(private_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(private_pem)
    os.chmod(private_path, 0o600)

    public_path.write_bytes(public_pem)
    os.chmod(public_path, 0o644)

    # Fail fast: the written private key must load exactly the way
    # CryptographicSigner loads it (unencrypted PEM, password=None).
    loaded = serialization.load_pem_private_key(
        private_path.read_bytes(), password=None
    )
    if not isinstance(loaded, rsa.RSAPrivateKey):
        raise TypeError("generated key did not reload as an RSA private key")

    return private_path, public_path


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--out-dir",
        default="keys",
        help="directory for the generated key files (default: keys)",
    )
    parser.add_argument(
        "--prefix",
        default="dev",
        help="filename prefix, e.g. dev -> dev_private.pem (default: dev)",
    )
    parser.add_argument(
        "--key-size",
        type=int,
        default=DEFAULT_KEY_SIZE,
        choices=ALLOWED_KEY_SIZES,
        help=f"RSA key size in bits (default: {DEFAULT_KEY_SIZE})",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="overwrite existing key files (otherwise refuse)",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    if not args.prefix or any(
        c in args.prefix for c in ("/", "\\", "..")
    ):
        print("error: --prefix must be a plain filename stem", file=sys.stderr)
        return 2

    try:
        private_key = generate_keypair(args.key_size)
        private_path, public_path = write_key_files(
            private_key, Path(args.out_dir), args.prefix, args.force
        )
    except (ValueError, FileExistsError, TypeError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    fingerprint = public_key_fingerprint(private_key)
    mode = stat.S_IMODE(private_path.stat().st_mode)

    print(f"private key: {private_path} (mode {mode:04o})")
    print(f"public key:  {public_path}")
    print(f"public key SHA-256 fingerprint: {fingerprint}")
    print(
        "WARNING: development/test key material only. "
        "Do not commit the private key. Load it at runtime via the "
        "RSA_PRIVATE_KEY_PEM environment variable or a secrets manager."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
