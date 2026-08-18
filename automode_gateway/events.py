from __future__ import annotations

import asyncio
import json
from typing import Any

from aiohttp import web


class EventBroker:
    def __init__(self) -> None:
        self.subscribers: set[asyncio.Queue[dict[str, Any]]] = set()

    def publish(self, event: str, data: dict[str, Any]) -> None:
        message = {"event": event, "data": data}
        for queue in list(self.subscribers):
            if queue.full():
                try:
                    queue.get_nowait()
                except asyncio.QueueEmpty:
                    pass
            queue.put_nowait(message)

    async def stream(self, request: web.Request) -> web.StreamResponse:
        response = web.StreamResponse(
            headers={
                "content-type": "text/event-stream",
                "cache-control": "no-cache",
                "connection": "keep-alive",
                "x-accel-buffering": "no",
            }
        )
        await response.prepare(request)
        queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=100)
        self.subscribers.add(queue)
        try:
            await response.write(b": connected\n\n")
            while True:
                try:
                    message = await asyncio.wait_for(queue.get(), timeout=20)
                    payload = json.dumps(message["data"], ensure_ascii=False, separators=(",", ":"))
                    await response.write(f"event: {message['event']}\ndata: {payload}\n\n".encode())
                except asyncio.TimeoutError:
                    await response.write(b": heartbeat\n\n")
        except (ConnectionResetError, asyncio.CancelledError):
            pass
        finally:
            self.subscribers.discard(queue)
        return response


EVENT_BROKER_KEY = web.AppKey("event_broker", EventBroker)
