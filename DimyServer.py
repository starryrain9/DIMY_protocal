#!/usr/bin/env python3
"""
DIMY backend server (centralized version for COMP9337 assignment).

Protocol (Scheme 2):
1) 4 bytes: total_len (big-endian, length of the following body)
2) 4 bytes: header_len (big-endian)
3) header_len bytes: UTF-8 JSON header
4) remaining bytes: binary payload

Header fields from client:
- ver: protocol version, currently 1
- op: "UPLOAD_CBF" or "QUERY_QBF"
- node_id: sender identifier (string, optional but recommended)
- payload_len: payload byte length
- ts: unix timestamp (optional)

Server response headers:
- ACK for uploads
- RESULT for query results, with match = "matched" | "not_matched"
- ERROR for malformed/unsupported requests
"""

from __future__ import annotations

import argparse
import json
import socketserver
import struct
import threading
from datetime import datetime
from typing import Dict, Optional, Tuple


PROTOCOL_VERSION = 1
DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 55000

# Lookup table for fast bit-count operations.
BIT_COUNT = [i.bit_count() for i in range(256)]


def log(message: str) -> None:
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{now}] {message}", flush=True)


def recv_exact(sock, length: int) -> Optional[bytes]:
    """Read exactly `length` bytes, or None if peer closed before any byte."""
    if length < 0:
        raise ValueError("length must be non-negative")
    buf = bytearray()
    while len(buf) < length:
        chunk = sock.recv(length - len(buf))
        if not chunk:
            if not buf:
                return None
            raise ConnectionError("Peer closed connection mid-frame")
        buf.extend(chunk)
    return bytes(buf)


def recv_frame(sock) -> Optional[Tuple[Dict, bytes]]:
    """
    Receive one framed message.
    Returns (header_dict, payload_bytes), or None if connection is closed cleanly.
    """
    size_prefix = recv_exact(sock, 4)
    if size_prefix is None:
        return None

    (total_len,) = struct.unpack(">I", size_prefix)
    if total_len < 4:
        raise ValueError(f"Invalid frame total_len={total_len}")

    body = recv_exact(sock, total_len)
    if body is None:
        raise ConnectionError("Missing frame body")

    (header_len,) = struct.unpack(">I", body[:4])
    if header_len > total_len - 4:
        raise ValueError(
            f"Invalid header_len={header_len}, total_len={total_len}"
        )

    header_raw = body[4 : 4 + header_len]
    payload = body[4 + header_len :]

    try:
        header = json.loads(header_raw.decode("utf-8"))
    except Exception as exc:
        raise ValueError(f"Header JSON decode failed: {exc}") from exc

    if not isinstance(header, dict):
        raise ValueError("Header must be a JSON object")

    payload_len = header.get("payload_len")
    if payload_len is None:
        header["payload_len"] = len(payload)
    elif payload_len != len(payload):
        raise ValueError(
            f"payload_len mismatch: header={payload_len}, actual={len(payload)}"
        )

    return header, payload


def send_frame(sock, header: Dict, payload: bytes = b"") -> None:
    """Send one framed message."""
    header = dict(header)
    header.setdefault("ver", PROTOCOL_VERSION)
    header["payload_len"] = len(payload)
    header_raw = json.dumps(header, separators=(",", ":"), ensure_ascii=True).encode(
        "utf-8"
    )
    body = struct.pack(">I", len(header_raw)) + header_raw + payload
    frame = struct.pack(">I", len(body)) + body
    sock.sendall(frame)


def count_common_bits(a: bytes, b: bytes) -> int:
    """Number of set bits in (a AND b)."""
    if len(a) != len(b):
        return 0
    total = 0
    for x, y in zip(a, b):
        total += BIT_COUNT[x & y]
    return total


class CBFStore:
    def __init__(self, min_common_bits: int = 3) -> None:
        self._min_common_bits = min_common_bits
        self._items = []
        self._lock = threading.Lock()

    def add(self, node_id: str, ts: Optional[int], cbf: bytes) -> int:
        with self._lock:
            self._items.append({"node_id": node_id, "ts": ts, "cbf": cbf})
            return len(self._items)

    def match(self, qbf: bytes) -> Tuple[bool, str, int]:
        with self._lock:
            snapshot = list(self._items)

        if not snapshot:
            return False, "", 0

        for item in snapshot:
            cbf = item["cbf"]
            if len(cbf) != len(qbf):
                continue
            common_bits = count_common_bits(cbf, qbf)
            if common_bits >= self._min_common_bits:
                return True, item["node_id"], common_bits

        return False, "", 0


class DimyTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, server_address, handler_cls, cbf_store: CBFStore):
        super().__init__(server_address, handler_cls)
        self.cbf_store = cbf_store


class DimyRequestHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        peer = f"{self.client_address[0]}:{self.client_address[1]}"
        log(f"Client connected: {peer}")

        while True:
            try:
                parsed = recv_frame(self.request)
                if parsed is None:
                    log(f"Client disconnected: {peer}")
                    return

                header, payload = parsed
                response_header = self.process_message(header, payload)
                send_frame(self.request, response_header)
            except (ConnectionError, OSError):
                log(f"Connection closed: {peer}")
                return
            except Exception as exc:
                log(f"Protocol error from {peer}: {exc}")
                try:
                    send_frame(
                        self.request,
                        {"op": "ERROR", "status": "error", "message": str(exc)},
                    )
                except Exception:
                    pass
                return

    def process_message(self, header: Dict, payload: bytes) -> Dict:
        op = header.get("op")
        ver = header.get("ver", PROTOCOL_VERSION)
        node_id = str(header.get("node_id", "unknown"))
        ts = header.get("ts")

        if ver != PROTOCOL_VERSION:
            return {
                "op": "ERROR",
                "status": "error",
                "message": f"Unsupported protocol version: {ver}",
            }

        if op == "UPLOAD_CBF":
            if not payload:
                return {
                    "op": "ERROR",
                    "status": "error",
                    "message": "UPLOAD_CBF requires non-empty payload",
                }
            total = self.server.cbf_store.add(node_id=node_id, ts=ts, cbf=payload)
            log(
                f"Stored CBF from node={node_id}, bytes={len(payload)}, "
                f"total_cbfs={total}"
            )
            return {
                "op": "ACK",
                "status": "stored",
                "cbf_count": total,
            }

        if op == "QUERY_QBF":
            if not payload:
                return {
                    "op": "ERROR",
                    "status": "error",
                    "message": "QUERY_QBF requires non-empty payload",
                }

            matched, matched_node, common_bits = self.server.cbf_store.match(payload)
            result = "matched" if matched else "not_matched"
            log(
                f"QBF query from node={node_id}, bytes={len(payload)}, "
                f"result={result}, matched_node={matched_node or '-'}, "
                f"common_bits={common_bits}"
            )
            return {
                "op": "RESULT",
                "match": result,
                "matched_node": matched_node,
                "common_bits": common_bits,
            }

        return {
            "op": "ERROR",
            "status": "error",
            "message": f"Unsupported op: {op}",
        }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="DIMY centralized backend server")
    parser.add_argument("host", nargs="?", default=DEFAULT_HOST)
    parser.add_argument("port", nargs="?", type=int, default=DEFAULT_PORT)
    parser.add_argument(
        "--min-common-bits",
        type=int,
        default=3,
        help="Minimum common set bits between QBF and CBF to mark as matched",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    cbf_store = CBFStore(min_common_bits=args.min_common_bits)
    server = DimyTCPServer((args.host, args.port), DimyRequestHandler, cbf_store)
    log(
        "DIMY server started on "
        f"{args.host}:{args.port} (min_common_bits={args.min_common_bits})"
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log("Shutting down server...")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
