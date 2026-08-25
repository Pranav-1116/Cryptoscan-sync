"""TCP connection with timeout."""

from __future__ import annotations

import socket
from typing import Any


def connect(host: str, port: int, *, timeout: float = 5.0) -> dict[str, Any]:
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        peer = sock.getpeername()
        return {"status": "OK", "socket": sock, "peer": peer, "host": host, "port": port}
    except ConnectionRefusedError:
        return {"status": "PORT_CLOSED", "host": host, "port": port}
    except TimeoutError:
        return {"status": "TIMEOUT", "host": host, "port": port}
    except OSError as exc:
        return {"status": "CONNECT_ERROR", "host": host, "port": port, "error": str(exc)}
