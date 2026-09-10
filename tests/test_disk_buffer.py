import os
import tempfile
import unittest
from pathlib import Path

from automode_gateway.disk_buffer import (
    DiskBuffer,
    DiskBufferFullError,
    DiskBufferError,
    EventPayloadTooLargeError,
)
from automode_gateway.evidence import generate_key, load_key


class DiskBufferTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.buffer_dir = Path(self.tempdir.name) / "buffer"
        self.raw_key = os.urandom(32)
        self.buffer = DiskBuffer(
            self.buffer_dir,
            evidence_key=self.raw_key,
            max_event_bytes=1024,
            max_buffer_bytes=4096,
        )

    def tearDown(self):
        self.tempdir.cleanup()

    def test_write_read_and_delete_cycle(self):
        event_id = "evt_001"
        data = b'{"hello": "world", "status": "ok"}'
        path = self.buffer.write(event_id, data)
        self.assertTrue(Path(path).is_file())
        self.assertTrue(self.buffer.exists(event_id))
        self.assertGreater(self.buffer.used_bytes, 0)

        # Raw file should not contain plaintext
        raw_on_disk = Path(path).read_bytes()
        self.assertNotIn(b"world", raw_on_disk)

        # Read should return exact plaintext
        read_back = self.buffer.read(event_id)
        self.assertEqual(read_back, data)

        # Delete removes file and frees quota
        deleted = self.buffer.delete(event_id)
        self.assertTrue(deleted)
        self.assertFalse(self.buffer.exists(event_id))
        self.assertEqual(self.buffer.used_bytes, 0)

    def test_aad_mismatch_fails_decryption(self):
        event_id = "evt_aad_1"
        data = b"secret token payload"
        self.buffer.write(event_id, data)

        # Target file exists
        file_path = self.buffer.directory / f"{event_id}.enc"
        tampered_id = "evt_aad_2"
        tampered_path = self.buffer.directory / f"{tampered_id}.enc"
        file_path.rename(tampered_path)

        # Reading with mismatched event_id (which acts as AAD) must fail
        with self.assertRaises(DiskBufferError):
            self.buffer.read(tampered_id)

    def test_single_event_size_limit(self):
        large_data = b"x" * 1025  # limit is 1024
        with self.assertRaises(EventPayloadTooLargeError):
            self.buffer.write("evt_large", large_data)

    def test_total_buffer_capacity_backpressure(self):
        chunk = b"a" * 800
        # Write first chunk
        self.buffer.write("evt_1", chunk)
        # Write second chunk
        self.buffer.write("evt_2", chunk)
        # Write third chunk
        self.buffer.write("evt_3", chunk)
        # Write fourth chunk
        self.buffer.write("evt_4", chunk)

        # 5th chunk would exceed 4096 bytes total buffer limit -> raises DiskBufferFullError
        with self.assertRaises(DiskBufferFullError):
            self.buffer.write("evt_5", chunk)

        # Confirm no silent drop: evt_1..4 are still intact
        self.assertEqual(self.buffer.read("evt_1"), chunk)
        self.assertEqual(self.buffer.read("evt_4"), chunk)

    def test_recovers_used_bytes_from_disk_on_startup(self):
        data = b"persisted test data"
        self.buffer.write("evt_persist", data)
        used_before = self.buffer.used_bytes
        self.assertGreater(used_before, 0)

        # New buffer pointing to same directory
        new_buffer = DiskBuffer(
            self.buffer_dir,
            evidence_key=self.raw_key,
            max_event_bytes=1024,
            max_buffer_bytes=4096,
        )
        self.assertEqual(new_buffer.used_bytes, used_before)
        self.assertTrue(new_buffer.exists("evt_persist"))
        self.assertEqual(new_buffer.read("evt_persist"), data)

    def test_atomic_write_leaves_no_temp_files(self):
        data = b"atomic write verification"
        self.buffer.write("evt_atomic", data)
        tmp_files = list(self.buffer.directory.glob(".tmp_*"))
        self.assertEqual(len(tmp_files), 0)


class DiskBufferAsyncTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.buffer_dir = Path(self.tempdir.name) / "buffer"
        self.raw_key = os.urandom(32)
        self.buffer = DiskBuffer(
            self.buffer_dir,
            evidence_key=self.raw_key,
        )

    async def asyncTearDown(self):
        self.tempdir.cleanup()

    async def test_async_write_read_delete(self):
        data = b"async test content"
        path = await self.buffer.async_write("evt_async", data)
        self.assertTrue(Path(path).is_file())

        read_data = await self.buffer.async_read("evt_async")
        self.assertEqual(read_data, data)

        deleted = await self.buffer.async_delete("evt_async")
        self.assertTrue(deleted)
        self.assertFalse(self.buffer.exists("evt_async"))


if __name__ == "__main__":
    unittest.main()
