"""IntegrityVerifier for SHA-256 verification, quarantine manifest writing, and AES-256-GCM encryption."""

import hashlib
import json
import os
from pathlib import Path
import secrets
import time
from typing import Any, Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from torpool.sanitizer import sanitize_url_for_manifest


class IntegrityVerifier:
    """
    Computes SHA-256 digest of downloaded files, compares against expected hash,
    optionally encrypts at rest with AES-256-GCM, and records sanitized manifest entries.
    """

    @staticmethod
    def compute_sha256(file_path: Path) -> str:
        """Compute SHA-256 hex digest of a file in 1 MiB blocks."""
        hasher = hashlib.sha256()
        with file_path.open("rb") as f:
            while chunk := f.read(1024 * 1024):
                hasher.update(chunk)
        return hasher.hexdigest()

    @classmethod
    def verify_and_record(
        cls,
        file_path: Path,
        url: str,
        expected_sha256: Optional[str] = None,
        manifest_path: Optional[Path] = None,
        encrypt: bool = False,
        passphrase: Optional[str] = None,
    ) -> tuple[bool, str, Path]:
        """
        Compute SHA-256, verify against expected_sha256 if given, encrypt if requested,
        and write sanitized manifest entry.
        Returns (passed, actual_sha256, final_file_path).
        """
        file_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(file_path.parent, 0o700)
        os.chmod(file_path, 0o600)

        actual_sha256 = cls.compute_sha256(file_path)
        file_size = file_path.stat().st_size

        passed = True
        if expected_sha256:
            passed = actual_sha256.lower() == expected_sha256.strip().lower()

        final_path = file_path
        if not passed:
            # Keep quarantined file marked .failed without overwriting existing failed artifacts
            failed_path = file_path.with_name(f"{file_path.name}.failed.{int(time.time())}")
            file_path.rename(failed_path)
            os.chmod(failed_path, 0o600)
            final_path = failed_path
        elif encrypt:
            secret = passphrase or os.environ.get("TORPOOL_PASSPHRASE") or secrets.token_hex(16)
            final_path = cls.encrypt_file_aes_gcm(file_path, secret)

        m_path = manifest_path or (file_path.parent / "manifest.json")
        cls._append_manifest(
            manifest_path=m_path,
            file_name=final_path.name,
            url=url,
            file_size=file_size,
            sha256=actual_sha256,
            expected_sha256=expected_sha256,
            status="VERIFIED" if passed else "FAILED_INTEGRITY",
            encrypted=bool(passed and encrypt),
        )
        return passed, actual_sha256, final_path

    @staticmethod
    def encrypt_file_aes_gcm(file_path: Path, passphrase: str) -> Path:
        """
        Encrypt file at rest using AES-256-GCM (key derived with Scrypt) and shred plaintext file.
        Format: 16-byte salt + 12-byte nonce + ciphertext+tag.
        """
        salt = secrets.token_bytes(16)
        nonce = secrets.token_bytes(12)
        kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
        key = kdf.derive(passphrase.encode("utf-8"))
        aesgcm = AESGCM(key)

        plaintext = file_path.read_bytes()
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)

        enc_path = file_path.with_name(f"{file_path.name}.enc")
        fd = os.open(enc_path, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
        try:
            os.fchmod(fd, 0o600)
            os.write(fd, salt + nonce + ciphertext)
        finally:
            os.close(fd)

        # Overwrite and unlink plaintext
        with file_path.open("r+b") as f:
            f.write(secrets.token_bytes(len(plaintext)))
            f.flush()
            os.fsync(f.fileno())
        file_path.unlink()
        return enc_path

    @staticmethod
    def _append_manifest(
        manifest_path: Path,
        file_name: str,
        url: str,
        file_size: int,
        sha256: str,
        expected_sha256: Optional[str],
        status: str,
        encrypted: bool,
    ) -> None:
        manifest_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        entries: list[dict[str, Any]] = []
        if manifest_path.exists():
            try:
                entries = json.loads(manifest_path.read_text(encoding="utf-8"))
            except Exception:
                entries = []

        entries.append(
            {
                "timestamp": time.time(),
                "file_name": file_name,
                "source_url": sanitize_url_for_manifest(url),
                "size_bytes": file_size,
                "sha256": sha256,
                "expected_sha256": expected_sha256,
                "status": status,
                "encrypted": encrypted,
            }
        )
        fd = os.open(manifest_path, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
        try:
            os.fchmod(fd, 0o600)
            os.write(fd, json.dumps(entries, indent=2).encode("utf-8"))
        finally:
            os.close(fd)
