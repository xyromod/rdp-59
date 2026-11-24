"""HTTP server with low-latency sockets for small gateway and agent responses.

This enables TCP_NODELAY on *accepted* sockets; by default the operating system
may delay a small body after the initial HTTP headers when Nagle is active.
"""
from __future__ import annotations
import socket
from http.server import ThreadingHTTPServer


class LowLatencyHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 128

    def get_request(self):
        connection, address = super().get_request()
        try:
            connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            connection.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        except OSError:
            pass  # non-TCP test socket / platform does not expose the option
        return connection, address
