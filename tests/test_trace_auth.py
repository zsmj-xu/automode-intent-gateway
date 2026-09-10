import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from aiohttp import ClientSession
from aiohttp.test_utils import TestServer
from yarl import URL

from automode_gateway.gateway import TRACE_STORE_KEY, create_app


class TraceAuthTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.environment = patch.dict(os.environ, {}, clear=True)
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.app = create_app(
            db_path=str(Path(self.tempdir.name) / "traces.db"),
            bind_host="0.0.0.0",
            admin_token="test-admin-token",
        )
        self.store = self.app[TRACE_STORE_KEY]
        self.payload = {
            "model": "test-model",
            "messages": [{"role": "user", "content": "synthetic audit content"}],
        }
        self.trace_id = self.store.create(
            protocol="openai_chat_completions",
            method="POST",
            path="/v1/chat/completions",
            payload=self.payload,
            headers={},
            session_id="test-session",
            latest_user_text="synthetic audit content",
            declared_tool_count=0,
        )
        self.server = TestServer(self.app)
        await self.server.start_server()
        self.addAsyncCleanup(self.server.close)
        self.client = ClientSession()
        self.addAsyncCleanup(self.client.close)

    async def test_trace_reads_reject_missing_and_invalid_credentials(self):
        paths = ("/traces?limit=1&session_id=test-session", f"/traces/{self.trace_id}")
        invalid_headers = (
            {},
            {"Authorization": "Bearer wrong-token"},
            {"x-automode-admin-token": "wrong-token"},
        )
        with patch.object(self.store, "list", wraps=self.store.list) as list_traces, \
                patch.object(self.store, "get", wraps=self.store.get) as get_trace:
            for path in paths:
                for method in ("GET", "HEAD"):
                    for headers in invalid_headers:
                        with self.subTest(path=path, method=method, headers=headers):
                            async with self.client.request(method, self.server.make_url(path), headers=headers) as response:
                                self.assertEqual(response.status, 401)
                                if method == "GET":
                                    self.assertEqual(await response.text(), "admin authentication required")
            list_traces.assert_not_called()
            get_trace.assert_not_called()

    async def test_encoded_paths_and_query_tokens_do_not_bypass_authentication(self):
        paths = (
            "/%74races",
            f"/tr%61ces/{self.trace_id}",
            f"/traces%2F{self.trace_id}",
            "/traces/",
            "/traces?token=test-admin-token",
            "/traces?x-automode-admin-token=test-admin-token",
            "/traces?limit=invalid",
            "/traces/missing-trace",
        )
        for path in paths:
            with self.subTest(path=path):
                url = URL(str(self.server.make_url("/"))[:-1] + path, encoded=True)
                async with self.client.get(url) as response:
                    self.assertEqual(response.status, 401)

    async def test_both_admin_headers_preserve_list_detail_and_head(self):
        for headers in (
            {"Authorization": "Bearer test-admin-token"},
            {"x-automode-admin-token": "test-admin-token"},
        ):
            with self.subTest(headers=headers):
                async with self.client.get(self.server.make_url("/traces?limit=1&session_id=test-session"), headers=headers) as response:
                    self.assertEqual(response.status, 200)
                    self.assertEqual((await response.json())["data"], self.store.list(1, "test-session"))
                async with self.client.get(self.server.make_url(f"/traces/{self.trace_id}"), headers=headers) as response:
                    self.assertEqual(response.status, 200)
                    self.assertEqual(await response.json(), self.store.get(self.trace_id))
                for path in ("/traces", f"/traces/{self.trace_id}"):
                    async with self.client.head(self.server.make_url(path), headers=headers) as response:
                        self.assertEqual(response.status, 200)

    async def test_authorized_errors_and_public_health_are_preserved(self):
        headers = {"Authorization": "Bearer test-admin-token"}
        for path, status, message in (
            ("/traces?limit=invalid", 400, "limit must be an integer"),
            ("/traces/missing-trace", 404, "trace not found"),
        ):
            async with self.client.get(self.server.make_url(path), headers=headers) as response:
                self.assertEqual(response.status, status)
                self.assertEqual(await response.text(), message)
        async with self.client.get(self.server.make_url("/health")) as response:
            self.assertEqual(response.status, 200)
        async with self.client.post(self.server.make_url("/v1/responses"), json={}) as response:
            self.assertEqual(response.status, 503)
            self.assertIn("upstream is not configured", await response.text())

    async def test_loopback_authentication_is_optional_but_enforces_configured_token(self):
        for token in ("", "test-admin-token"):
            with self.subTest(token_configured=bool(token)), patch.dict(os.environ, {"AUTOMODE_ADMIN_TOKEN": token}):
                app = create_app(db_path=str(Path(self.tempdir.name) / f"loopback-{bool(token)}.db"))
                async with TestServer(app) as server:
                    async with self.client.get(server.make_url("/traces")) as response:
                        self.assertEqual(response.status, 401 if token else 200)
                        if not token:
                            self.assertEqual(await response.json(), {"data": []})
                    if token:
                        async with self.client.get(server.make_url("/traces"), headers={"Authorization": f"Bearer {token}"}) as response:
                            self.assertEqual(response.status, 200)
                            self.assertEqual(await response.json(), {"data": []})


if __name__ == "__main__":
    unittest.main()
