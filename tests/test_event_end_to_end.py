"""Regression coverage through the real standalone application and ingress API."""
import asyncio
import base64
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from aiohttp.test_utils import TestClient, TestServer

from automode_gateway.admin_api import STORE_KEY
from automode_gateway.gateway import create_app


class EventEndToEndTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        directory = Path(self.directory.name)
        key = directory / 'evidence.key'
        key.write_bytes(base64.urlsafe_b64encode(b'e' * 32))
        key.chmod(0o600)
        self.environment = patch.dict(os.environ, {
            'AUTOMODE_EVIDENCE_KEY_FILE': str(key),
            'AUTOMODE_DISK_BUFFER_DIR': str(directory / 'buffer'),
            'AUTOMODE_ADMIN_TOKEN': 'synthetic-admin',
            'AUTOMODE_FAST_URL': 'https://reviewer.invalid',
            'AUTOMODE_FAST_MODEL': 'synthetic-reviewer',
        }, clear=True)
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.transport = patch('automode_gateway.llm_classifier._http_transport', side_effect=TimeoutError('synthetic outage'))
        self.transport_mock = self.transport.start()
        self.addCleanup(self.transport.stop)
        self.app = create_app(upstream=None, db_path=str(directory / 'events.db'))
        self.store = self.app[STORE_KEY]
        for source in ('one', 'two'):
            self.store.create_source(id=source, name=source, token='synthetic-' + source)
        self.client = TestClient(TestServer(self.app))
        await self.client.start_server()
        self.addAsyncCleanup(self.client.close)

    def event(self, event_id, source='one', content='hello'):
        return {
            'version': '1', 'event_id': event_id, 'source_id': source, 'call_id': event_id,
            'event_type': 'request', 'protocol': 'openai_chat_completions',
            'capture_stage': 'model_outbound', 'content_integrity': 'complete',
            'timestamp': '2026-09-09T00:00:00Z', 'is_realtime': False,
            'payload': {'model': 'synthetic', 'messages': [{'role': 'user', 'content': content}]},
        }

    async def submit(self, event):
        response = await self.client.post('/v1/events', json=event, headers={'authorization': 'Bearer synthetic-' + event['source_id']})
        self.assertEqual(response.status, 202, await response.text())
        return await response.json()

    async def result(self, accepted, source='one'):
        for _ in range(200):
            response = await self.client.get(accepted['status_url'], headers={'authorization': 'Bearer synthetic-' + source})
            self.assertEqual(response.status, 200, await response.text())
            data = await response.json()
            if data['processing_status'] in ('completed', 'failed'):
                return data
            await asyncio.sleep(0.025)
        self.fail('accepted event did not reach a terminal state')

    async def test_two_sources_share_external_id_without_payload_collision(self):
        accepted = await asyncio.gather(self.submit(self.event('shared', 'one')), self.submit(self.event('shared', 'two')))
        for item, source in zip(accepted, ('one', 'two')):
            result = await self.result(item, source)
            self.assertEqual(result['source_id'], source)
        one = self.store.get_event_by_source_and_id('one', 'shared')
        two = self.store.get_event_by_source_and_id('two', 'shared')
        self.assertNotEqual(one['id'], two['id'])

    async def test_reusing_id_with_changed_destination_is_a_conflict(self):
        event = self.event('destination-conflict')
        await self.submit(event)
        event['model_destination'] = {'upstream': 'https://other.invalid'}
        response = await self.client.post('/v1/events', json=event, headers={'authorization': 'Bearer synthetic-one'})
        self.assertEqual(response.status, 409, await response.text())

    async def test_reviewer_timeout_retains_alert_and_encrypted_evidence(self):
        secret = 'api_key=syntheticRegressionSecret123456789012345'
        accepted = await self.submit(self.event('timeout', content=secret))
        result = await self.result(accepted)
        self.assertEqual(result['llm_status'], 'failed')
        self.assertGreater(self.transport_mock.call_count, 0)
        observed = json.dumps(self.transport_mock.call_args_list, default=str)
        self.assertNotIn(secret, observed)
        internal = self.store.get_event_by_source_and_id('one', 'timeout')['id']
        with self.store._connect() as connection:
            alerts = connection.execute('SELECT * FROM alerts WHERE event_id=?', (internal,)).fetchall()
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]['severity'], 'critical')
        self.assertEqual(alerts[0]['review_status'], 'failed')
        self.assertTrue(alerts[0]['evidence_id'])
        evidence = self.store.evidence(alerts[0]['evidence_id'], actor='test', purpose='regression', source='loopback')
        self.assertIn(secret, json.dumps(evidence['payload']))

    async def test_missing_body_never_completes_as_allow(self):
        event = self.event('missing')
        event.update(content_integrity='missing', payload=None)
        result = await self.result(await self.submit(event))
        verdict = result['rule_verdict'] or {}
        self.assertNotEqual(verdict.get('decision', verdict.get('rule_decision')), 'allow')

    async def test_registered_target_is_used_by_event_path(self):
        self.store.create_destination({'name': 'internal', 'upstream_pattern': 'https://internal.invalid', 'model_pattern': '*', 'trust': 'trusted', 'enabled': True})
        event = self.event('internal')
        event['model_destination'] = {'upstream': 'https://internal.invalid'}
        result = await self.result(await self.submit(event))
        self.assertEqual(result['rule_verdict']['destination']['trust'], 'trusted')

    async def test_orphan_sse_response_keeps_redacted_tools_for_late_request(self):
        secret = 'syntheticToolSecret123456789012345'
        chunk = {'choices': [{'delta': {'tool_calls': [{'index': 0, 'id': 'tool-1', 'type': 'function',
            'function': {'name': 'example_tool', 'arguments': json.dumps({'password': secret})}}]}}]}
        response_event = self.event('response-first')
        response_event.update(event_type='response', call_id='late-call',
            payload='data: ' + json.dumps(chunk) + '\n\ndata: [DONE]\n\n')
        result = await self.result(await self.submit(response_event))
        self.assertEqual(result['association_status'], 'request_missing')
        response_row = self.store.get_event_by_source_and_id('one', 'response-first')
        evidence = json.loads(response_row['response_evidence_json'])
        self.assertEqual(len(evidence), 1)
        self.assertIn('example_tool', json.dumps(evidence))
        self.assertNotIn(secret, json.dumps(evidence))
        request_event = self.event('late-request')
        request_event['call_id'] = 'late-call'
        result = await self.result(await self.submit(request_event))
        self.assertEqual(result['association_status'], 'associated')
        self.assertEqual(self.store.get_event_by_source_and_id('one', 'response-first')['association_status'], 'associated')

    async def test_truncated_visible_text_does_not_become_a_complete_allow(self):
        event = self.event('truncated')
        event['content_integrity'] = 'truncated'
        result = await self.result(await self.submit(event))
        verdict = result['rule_verdict'] or {}
        self.assertNotEqual(verdict.get('decision', verdict.get('rule_decision')), 'allow')
