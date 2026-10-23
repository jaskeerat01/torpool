"""IntegrityVerifier for SHA-256 verification, quarantine manifest writing, and streamed AES-256-GCM encryption."""

import hashlib
import hmac
import json
import os
import secrets
import struct
import threading
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from torpool.sanitizer import sanitize_url_for_manifest
from torpool.state_store import ChunkRecord


class VerificationError(Exception):
    """Raised when file integrity verification or decryption fails."""


@dataclass
class EncryptedChunkRecord:
    chunk_id: int
    start_byte: int
    end_byte: int
    ciphertext_offset: int
    ciphertext_length: int
    nonce_hex: str
    tag_hex: str


class EncryptedFileSession:
    """
    Manages writing AES-256-GCM encrypted chunks directly to disk during download.
    Ensures that ONLY ciphertext exists on disk throughout the entire transfer.
    Maintains an authenticated record index mapping logical offsets to ciphertext offsets.
    """

    def __init__(
        self,
        enc_path: Path,
        idx_path: Path,
        passphrase: str,
        total_size: int,
    ) -> None:
        self.enc_path = enc_path
        self.idx_path = idx_path
        self.total_size = total_size
        self._salt = secrets.token_bytes(16)
        # Derive 32 bytes for AES-256-GCM and 32 bytes for HMAC-SHA256 index auth
        kdf = Scrypt(salt=self._salt, length=64, n=2**14, r=8, p=1)
        derived = kdf.derive(passphrase.encode("utf-8"))
        self._aes_key = derived[:32]
        self._hmac_key = derived[32:]
        self._aesgcm = AESGCM(self._aes_key)
        self._lock = threading.Lock()
        self._records: dict[int, EncryptedChunkRecord] = {}
        self._current_offset: int = 0

        self.enc_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.enc_path.parent, 0o700)
        fd = os.open(self.enc_path, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
        os.close(fd)

    def write_chunk(self, chunk: ChunkRecord, plaintext_data: bytes) -> None:
        """Encrypt chunk with AES-256-GCM in memory and write ciphertext to disk."""
        nonce = secrets.token_bytes(12)
        aad = struct.pack(">QQI", chunk.start_byte, chunk.end_byte, chunk.chunk_id)
        ct_with_tag = self._aesgcm.encrypt(nonce, plaintext_data, aad)
        tag = ct_with_tag[-16:]

        with self._lock:
            offset = self._current_offset
            fd = os.open(self.enc_path, os.O_WRONLY)
            try:
                os.lseek(fd, offset, os.SEEK_SET)
                os.write(fd, ct_with_tag)
            finally:
                os.close(fd)
            self._current_offset += len(ct_with_tag)

            record = EncryptedChunkRecord(
                chunk_id=chunk.chunk_id,
                start_byte=chunk.start_byte,
                end_byte=chunk.end_byte,
                ciphertext_offset=offset,
                ciphertext_length=len(ct_with_tag),
                nonce_hex=nonce.hex(),
                tag_hex=tag.hex(),
            )
            self._records[chunk.chunk_id] = record

    def finalize(self, expected_sha256: Optional[str] = None) -> tuple[Path, Path, str]:
        """Compute plaintext SHA-256 and write authenticated index file with HMAC-SHA256."""
        hasher = hashlib.sha256()
        sorted_records = sorted(self._records.values(), key=lambda r: r.start_byte)
        with open(self.enc_path, "rb") as f:
            for rec in sorted_records:
                f.seek(rec.ciphertext_offset)
                ct_with_tag = f.read(rec.ciphertext_length)
                nonce = bytes.fromhex(rec.nonce_hex)
                aad = struct.pack(">QQI", rec.start_byte, rec.end_byte, rec.chunk_id)
                pt = self._aesgcm.decrypt(nonce, ct_with_tag, aad)
                hasher.update(pt)

        actual_sha256 = hasher.hexdigest()

        payload = {
            "magic": "TPENC_IDX_V1",
            "salt": self._salt.hex(),
            "total_size": self.total_size,
            "sha256": actual_sha256,
            "expected_sha256": expected_sha256,
            "chunks": [asdict(r) for r in sorted_records],
        }
        payload_bytes = json.dumps(payload, sort_keys=True).encode("utf-8")
        mac = hmac.new(self._hmac_key, payload_bytes, hashlib.sha256).hexdigest()

        index_data = {
            "payload": payload,
            "hmac": mac,
        }

        self.idx_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.idx_path.parent, 0o700)
        fd = os.open(self.idx_path, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
        try:
            os.fchmod(fd, 0o600)
            os.write(fd, json.dumps(index_data, indent=2).encode("utf-8"))
        finally:
            os.close(fd)

        return self.enc_path, self.idx_path, actual_sha256


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

    @staticmethod
    def shred_file(file_path: Path) -> None:
        """Overwrite file with random bytes, flush, and unlink."""
        if not file_path.exists() or not file_path.is_file():
            return
        try:
            size = file_path.stat().st_size
            with file_path.open("r+b") as f:
                remaining = size
                block = 65536
                while remaining > 0:
                    to_write = min(block, remaining)
                    f.write(secrets.token_bytes(to_write))
                    remaining -= to_write
                f.flush()
                os.fsync(f.fileno())
        except Exception:
            pass
        finally:
            try:
                file_path.unlink()
            except Exception:
                pass

    @classmethod
    def verify_and_record(
        cls,
        file_path: Path,
        url: str,
        expected_sha256: Optional[str] = None,
        manifest_path: Optional[Path] = None,
        encrypt: bool = False,
        passphrase: Optional[str] = None,
        actual_sha256_override: Optional[str] = None,
    ) -> tuple[bool, str, Path]:
        """
        Verify file against expected_sha256, handle encryption if requested,
        and append sanitized manifest entry.
        Returns (passed, actual_sha256, final_file_path).
        """
        file_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(file_path.parent, 0o700)
        os.chmod(file_path, 0o600)

        actual_sha256 = actual_sha256_override or cls.compute_sha256(file_path)
        file_size = file_path.stat().st_size

        passed = True
        if expected_sha256:
            passed = actual_sha256.lower() == expected_sha256.strip().lower()

        final_path = file_path
        if not passed:
            failed_path = file_path.with_name(f"{file_path.name}.failed.{int(time.time())}")
            file_path.rename(failed_path)
            os.chmod(failed_path, 0o600)
            final_path = failed_path
        elif encrypt and not file_path.name.endswith(".enc"):
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

    @classmethod
    def decrypt_file(
        cls,
        enc_path: Path,
        out_path: Path,
        passphrase: str,
        idx_path: Optional[Path] = None,
    ) -> tuple[int, str]:
        """
        Recover plaintext from an encrypted file to a user-chosen destination with 0600 permissions.
        Never logs or stores the passphrase.
        Returns (recovered_bytes, sha256_digest).
        """
        if not enc_path.exists():
            raise VerificationError(f"Encrypted file does not exist: {enc_path}")

        target_idx = idx_path
        if not target_idx or not target_idx.exists():
            candidates = [
                enc_path.with_suffix(".idx"),
                Path(str(enc_path) + ".idx"),
                enc_path.parent / (enc_path.stem + ".idx"),
            ]
            for c in candidates:
                if c.exists():
                    target_idx = c
                    break

        if target_idx and target_idx.exists():
            try:
                raw_idx = json.loads(target_idx.read_text(encoding="utf-8"))
            except Exception as exc:
                raise VerificationError(f"Failed to parse index file {target_idx}: {exc}") from exc

            payload = raw_idx.get("payload", {})
            stored_hmac = raw_idx.get("hmac", "")
            salt = bytes.fromhex(payload.get("salt", ""))

            kdf = Scrypt(salt=salt, length=64, n=2**14, r=8, p=1)
            derived = kdf.derive(passphrase.encode("utf-8"))
            aes_key = derived[:32]
            hmac_key = derived[32:]

            payload_bytes = json.dumps(payload, sort_keys=True).encode("utf-8")
            calculated_hmac = hmac.new(hmac_key, payload_bytes, hashlib.sha256).hexdigest()
            if not hmac.compare_digest(calculated_hmac, stored_hmac):
                raise VerificationError(
                    "Index authentication failed: incorrect passphrase or corrupted index."
                )

            total_size = payload.get("total_size", 0)
            chunks = payload.get("chunks", [])

            out_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            os.chmod(out_path.parent, 0o700)
            fd = os.open(out_path, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
            try:
                os.fchmod(fd, 0o600)
                if total_size > 0:
                    os.ftruncate(fd, total_size)
            finally:
                os.close(fd)

            aesgcm = AESGCM(aes_key)
            hasher = hashlib.sha256()

            with open(enc_path, "rb") as f_enc, open(out_path, "r+b") as f_out:
                for chunk_info in sorted(chunks, key=lambda c: c["start_byte"]):
                    f_enc.seek(chunk_info["ciphertext_offset"])
                    ct_with_tag = f_enc.read(chunk_info["ciphertext_length"])
                    nonce = bytes.fromhex(chunk_info["nonce_hex"])
                    aad = struct.pack(
                        ">QQI",
                        chunk_info["start_byte"],
                        chunk_info["end_byte"],
                        chunk_info["chunk_id"],
                    )
                    try:
                        plaintext = aesgcm.decrypt(nonce, ct_with_tag, aad)
                    except Exception as exc:
                        raise VerificationError(
                            f"Decryption failed for chunk {chunk_info['chunk_id']}: {exc}"
                        ) from exc

                    f_out.seek(chunk_info["start_byte"])
                    f_out.write(plaintext)
                    hasher.update(plaintext)

                f_out.flush()
                os.fsync(f_out.fileno())

            actual_sha256 = hasher.hexdigest()
            expected_sha256 = payload.get("sha256")
            if expected_sha256 and actual_sha256.lower() != expected_sha256.lower():
                cls.shred_file(out_path)
                raise VerificationError(
                    f"Decrypted file SHA-256 mismatch: expected {expected_sha256}, got {actual_sha256}"
                )

            return total_size, actual_sha256

        # Fallback to single-pass format
        raw = enc_path.read_bytes()
        if len(raw) < 28:
            raise VerificationError(f"Encrypted file {enc_path} is too small to be valid.")
        salt = raw[:16]
        nonce = raw[16:28]
        ciphertext = raw[28:]

        kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
        key = kdf.derive(passphrase.encode("utf-8"))
        aesgcm = AESGCM(key)

        try:
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        except Exception as exc:
            raise VerificationError(f"Decryption failed (incorrect passphrase): {exc}") from exc

        out_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(out_path.parent, 0o700)
        fd = os.open(out_path, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
        try:
            os.fchmod(fd, 0o600)
            os.write(fd, plaintext)
        finally:
            os.close(fd)

        actual_sha256 = hashlib.sha256(plaintext).hexdigest()
        return len(plaintext), actual_sha256

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
