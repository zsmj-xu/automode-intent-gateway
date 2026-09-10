from __future__ import annotations

import asyncio
import os
from pathlib import Path
import threading
from typing import Any
import uuid

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


DEFAULT_MAX_EVENT_BYTES: int = 32 * 1024 * 1024  # 32 MiB
DEFAULT_MAX_BUFFER_BYTES: int = 1024 * 1024 * 1024  # 1 GiB


class DiskBufferError(Exception):
    """Base exception for disk buffer operations."""


class EventPayloadTooLargeError(DiskBufferError):
    """Payload exceeds maximum single event size limit."""


class DiskBufferFullError(DiskBufferError):
    """Disk buffer capacity exceeded (backpressure)."""


class DiskBuffer:
    """Encrypted disk buffer for buffering event payloads before / during analysis."""

    def __init__(
        self,
        directory: str | Path,
        evidence_key: bytes,
        max_event_bytes: int = DEFAULT_MAX_EVENT_BYTES,
        max_buffer_bytes: int = DEFAULT_MAX_BUFFER_BYTES,
    ) -> None:
        if not evidence_key or len(evidence_key) != 32:
            raise ValueError("valid 32-byte evidence_key is required for DiskBuffer")
        self.directory = Path(directory).resolve()
        self.directory.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.directory, 0o700)
        except OSError:
            pass
        self.evidence_key = evidence_key
        self.max_event_bytes = max_event_bytes
        self.max_buffer_bytes = max_buffer_bytes
        self._lock = threading.Lock()
        self._used_bytes = 0
        self.purge_tmp_files()
        self._scan_used_bytes()

    def _path_for_id(self, internal_id: str) -> Path:
        """Return a buffer path for an internal ID and reject path traversal."""
        value = str(internal_id)
        if not value or value in {".", ".."} or Path(value).name != value:
            raise DiskBufferError("event buffer key must be a single path component")
        return self.directory / f"{value}.enc"

    def _scan_used_bytes(self) -> None:
        total = 0
        for item in self.directory.glob("*.enc"):
            if item.is_file():
                try:
                    total += item.stat().st_size
                except OSError:
                    pass
        self._used_bytes = total

    @property
    def used_bytes(self) -> int:
        with self._lock:
            return self._used_bytes

    def write(self, event_id: str, data: bytes) -> str:
        if len(data) > self.max_event_bytes:
            raise EventPayloadTooLargeError(
                f"payload size {len(data)} exceeds single event limit {self.max_event_bytes}"
            )

        nonce = os.urandom(12)
        aad = event_id.encode("utf-8")
        aesgcm = AESGCM(self.evidence_key)
        ciphertext = aesgcm.encrypt(nonce, data, aad)
        file_content = nonce + ciphertext
        content_size = len(file_content)

        target_path = self._path_for_id(event_id)
        tmp_path = self.directory / f".tmp_{target_path.stem}_{uuid.uuid4().hex}"

        with self._lock:
            existing_size = target_path.stat().st_size if target_path.exists() else 0
            net_increase = content_size - existing_size
            if self._used_bytes + net_increase > self.max_buffer_bytes:
                raise DiskBufferFullError(
                    f"disk buffer capacity exceeded: used={self._used_bytes}, adding={net_increase}, max={self.max_buffer_bytes}"
                )

            try:
                with open(tmp_path, "wb") as f:
                    f.write(file_content)
                    f.flush()
                    os.fsync(f.fileno())
                os.replace(tmp_path, target_path)
                # Persist the directory entry as well as the file contents so a
                # successful ingress response implies durable file naming.
                try:
                    dir_fd = os.open(self.directory, os.O_RDONLY)
                    try:
                        os.fsync(dir_fd)
                    finally:
                        os.close(dir_fd)
                except OSError:
                    # Some filesystems do not allow directory fsync; the atomic
                    # replace still prevents partial files from being observed.
                    pass
                self._used_bytes += net_increase
            finally:
                if tmp_path.exists():
                    tmp_path.unlink(missing_ok=True)

        return str(target_path)

    def read(self, event_id: str) -> bytes:
        target_path = self._path_for_id(event_id)
        if not target_path.exists():
            raise FileNotFoundError(f"buffer file not found for event '{event_id}'")

        raw = target_path.read_bytes()
        if len(raw) < 28:  # 12 nonce + 16 tag minimum
            raise DiskBufferError(f"corrupt buffer file for event '{event_id}'")

        nonce = raw[:12]
        ciphertext = raw[12:]
        aad = event_id.encode("utf-8")
        try:
            aesgcm = AESGCM(self.evidence_key)
            return aesgcm.decrypt(nonce, ciphertext, aad)
        except Exception as exc:
            raise DiskBufferError(f"decryption failed for event '{event_id}': {exc}") from exc

    def delete(self, event_id: str) -> bool:
        target_path = self._path_for_id(event_id)
        with self._lock:
            if target_path.exists():
                size = target_path.stat().st_size
                target_path.unlink(missing_ok=True)
                self._used_bytes = max(0, self._used_bytes - size)
                return True
            return False

    def exists(self, event_id: str) -> bool:
        try:
            return self._path_for_id(event_id).is_file()
        except DiskBufferError:
            return False

    def list_event_ids(self) -> list[str]:
        return [p.stem for p in self.directory.glob("*.enc") if p.is_file()]

    def purge_tmp_files(self) -> int:
        count = 0
        for tmp in self.directory.glob(".tmp_*"):
            try:
                tmp.unlink(missing_ok=True)
                count += 1
            except OSError:
                pass
        return count

    def usage_stats(self) -> dict[str, Any]:
        with self._lock:
            return {
                "used_bytes": self._used_bytes,
                "max_buffer_bytes": self.max_buffer_bytes,
                "max_event_bytes": self.max_event_bytes,
                "file_count": len(self.list_event_ids()),
            }

    async def async_write(self, event_id: str, data: bytes) -> str:
        return await asyncio.to_thread(self.write, event_id, data)

    async def async_read(self, event_id: str) -> bytes:
        return await asyncio.to_thread(self.read, event_id)

    async def async_delete(self, event_id: str) -> bool:
        return await asyncio.to_thread(self.delete, event_id)
