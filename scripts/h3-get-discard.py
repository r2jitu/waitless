#!/usr/bin/env python3
# Minimal HTTP/3 GET that reads + DISCARDS the response body (counting
# bytes + non-zero bytes), stopping after `limit` bytes. Used to drive a
# large h3 streamed response (/stream) so we can watch the SERVER's heap
# stay bounded (the client never buffers the whole body either).
#   usage: h3get.py <host> <port> <path> <limit_bytes>
import asyncio
import sys

import aioquic.asyncio.client as aclient
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration

HOST, PORT, PATH, LIMIT = sys.argv[1], int(sys.argv[2]), sys.argv[3], int(sys.argv[4])


class GetProbe(QuicConnectionProtocol):
    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self.h3 = H3Connection(self._quic)
        self.done = asyncio.get_event_loop().create_future()
        self.total = 0
        self.nonzero = 0
        self.status = None

    def quic_event_received(self, event):
        for e in self.h3.handle_event(event):
            if isinstance(e, HeadersReceived):
                for k, v in e.headers:
                    if k == b":status":
                        self.status = v
                if e.stream_ended and not self.done.done():
                    self.done.set_result(True)
            elif isinstance(e, DataReceived):
                self.total += len(e.data)
                self.nonzero += len(e.data) - e.data.count(0)  # C-fast
                if (self.total >= LIMIT or e.stream_ended) and not self.done.done():
                    self.done.set_result(True)


async def main():
    cfg = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN)
    cfg.verify_mode = False
    cfg.idle_timeout = 30.0
    async with aclient.connect(
        HOST, PORT, configuration=cfg, create_protocol=GetProbe, wait_connected=True
    ) as client:
        sid = client._quic.get_next_available_stream_id()
        client.h3.send_headers(
            stream_id=sid,
            headers=[
                (b":method", b"GET"),
                (b":scheme", b"https"),
                (b":authority", f"{HOST}:{PORT}".encode()),
                (b":path", PATH.encode()),
            ],
            end_stream=True,
        )
        client.transmit()
        await asyncio.wait_for(client.done, timeout=30.0)
        print(f"status={client.status} total={client.total} nonzero={client.nonzero}")


asyncio.run(main())
