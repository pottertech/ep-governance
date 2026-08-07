"""Encrypted key file support for EP-Governance.

Provides functions to encrypt and decrypt Ed25519 signing keys at rest.
Uses AES-256-CBC with PBKDF2 key derivation via openssl.

Usage:
    # Encrypt a key:
    python3 -c "
    from ep_governance.key_crypto import encrypt_key_file
    encrypt_key_file('ep_signing_prod.key', 'ep_signing_prod.key.enc', 'passphrase')
    "

    # Decrypt at runtime:
    from ep_governance.key_crypto import decrypt_key_file
    key_bytes = decrypt_key_file('ep_signing_prod.key.enc', 'passphrase')
    # key_bytes is the raw 32-byte Ed25519 private key
"""

from __future__ import annotations

import os
import subprocess
import tempfile
from typing import Optional


def encrypt_key_file(
    input_path: str,
    output_path: str,
    passphrase: str,
) -> None:
    """Encrypt a key file using AES-256-CBC with PBKDF2.

    Args:
        input_path: Path to the raw key file (32 bytes).
        output_path: Path to write the encrypted file.
        passphrase: Encryption passphrase.
    """
    result = subprocess.run(
        [
            "openssl", "enc", "-aes-256-cbc", "-salt", "-pbkdf2",
            "-in", input_path,
            "-out", output_path,
            "-pass", f"pass:{passphrase}",
        ],
        capture_output=True, text=True, timeout=10,
    )
    if result.returncode != 0:
        raise RuntimeError(f"Encryption failed: {result.stderr}")
    # Set restrictive permissions on the encrypted file
    os.chmod(output_path, 0o600)


def decrypt_key_file(
    input_path: str,
    passphrase: str,
) -> bytes:
    """Decrypt a key file and return the raw key bytes.

    Args:
        input_path: Path to the encrypted key file.
        passphrase: Decryption passphrase.

    Returns:
        Raw key bytes (e.g., 32 bytes for Ed25519).
    """
    result = subprocess.run(
        [
            "openssl", "enc", "-d", "-aes-256-cbc", "-pbkdf2",
            "-in", input_path,
            "-pass", f"pass:{passphrase}",
        ],
        capture_output=True, timeout=10,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"Decryption failed: {result.stderr.decode('utf-8', errors='replace')}"
        )
    return result.stdout


def load_decrypted_key_manager(
    encrypted_key_path: str,
    passphrase: str,
):
    """Load a KeyManager from an encrypted key file.

    Decrypts the key to a temporary file, loads it into a KeyManager,
    and securely deletes the temp file.

    Args:
        encrypted_key_path: Path to the encrypted key file.
        passphrase: Decryption passphrase.

    Returns:
        A KeyManager instance with the decrypted key loaded.
    """
    from .authorizations import KeyManager

    key_bytes = decrypt_key_file(encrypted_key_path, passphrase)

    # Write to a temp file, load, then delete
    fd, temp_path = tempfile.mkstemp(prefix="ep_key_", suffix=".tmp")
    try:
        os.write(fd, key_bytes)
        os.close(fd)
        os.chmod(temp_path, 0o600)

        km = KeyManager()
        km.load_private_key(temp_path)
        return km
    finally:
        # Securely delete the temp file
        try:
            # Overwrite with zeros before deleting
            with open(temp_path, "wb") as f:
                f.write(b"\x00" * len(key_bytes))
            os.unlink(temp_path)
        except OSError:
            pass


def resolve_signing_key(
    key_file_path: str,
    passphrase: Optional[str] = None,
):
    """Resolve a signing key from either a plain or encrypted file.

    If the path ends with '.enc', decrypts using the passphrase
    (from EP_SIGNING_KEY_PASSPHRASE env var if not provided).
    Otherwise, loads directly.

    Args:
        key_file_path: Path to the key file (plain or .enc).
        passphrase: Optional passphrase for encrypted files.

    Returns:
        A KeyManager instance.
    """
    from .authorizations import KeyManager

    if key_file_path.endswith(".enc"):
        if passphrase is None:
            passphrase = os.environ.get("EP_SIGNING_KEY_PASSPHRASE", "")
        if not passphrase:
            raise RuntimeError(
                "EP_SIGNING_KEY_PASSPHRASE is required for encrypted key files"
            )
        return load_decrypted_key_manager(key_file_path, passphrase)
    else:
        km = KeyManager()
        km.load_private_key(key_file_path)
        return km