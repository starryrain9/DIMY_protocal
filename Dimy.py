#!/usr/bin/env python3
"""
DIMY frontend node for COMP9337 assignment.

Usage:
    python Dimy.py [t] [k] [n] [p] [Server_IP] [Server_Port]

Example:
    python Dimy.py 15 3 5 50 127.0.0.1 55000 --node-id N1
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import secrets
import socket
import struct
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Tuple


PROTOCOL_VERSION = 1
BF_BYTES = 100 * 1024
BF_BITS = BF_BYTES * 8
BF_HASHES = 3
UDP_RECV_BUFFER = 65536

# 2048-bit MODP group prime (RFC 3526 group 14) and generator.
DH_P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08"
    "8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD"
    "3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E"
    "7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899F"
    "A5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05"
    "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C"
    "62F356208552BB9ED529077096966D670C354E4ABC9804F174"
    "6C08CA237327FFFFFFFFFFFFFFFF",
    16,
)
DH_G = 2

# Lookup table for byte bit-count.
BIT_COUNT = [i.bit_count() for i in range(256)]


def log(node_id: str, message: str) -> None:
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{now}] [{node_id}] {message}", flush=True)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def recv_exact(sock: socket.socket, length: int) -> Optional[bytes]:
    if length < 0:
        raise ValueError("length must be non-negative")
    buf = bytearray()
    while len(buf) < length:
        chunk = sock.recv(length - len(buf))
        if not chunk:
            if not buf:
                return None
            raise ConnectionError("Connection closed mid-frame")
        buf.extend(chunk)
    return bytes(buf)


def send_frame(sock: socket.socket, header: Dict, payload: bytes = b"") -> None:
    header = dict(header)
    header.setdefault("ver", PROTOCOL_VERSION)
    header["payload_len"] = len(payload)
    header_raw = json.dumps(header, separators=(",", ":"), ensure_ascii=True).encode(
        "utf-8"
    )
    body = struct.pack(">I", len(header_raw)) + header_raw + payload
    frame = struct.pack(">I", len(body)) + body
    sock.sendall(frame)


def recv_frame(sock: socket.socket) -> Optional[Tuple[Dict, bytes]]:
    size_prefix = recv_exact(sock, 4)
    if size_prefix is None:
        return None
    (total_len,) = struct.unpack(">I", size_prefix)
    if total_len < 4:
        raise ValueError(f"Invalid total_len={total_len}")
    body = recv_exact(sock, total_len)
    if body is None:
        raise ConnectionError("Missing body")
    (header_len,) = struct.unpack(">I", body[:4])
    if header_len > total_len - 4:
        raise ValueError(
            f"Invalid header_len={header_len}, total_len={total_len}"
        )
    header_raw = body[4 : 4 + header_len]
    payload = body[4 + header_len :]
    header = json.loads(header_raw.decode("utf-8"))
    if not isinstance(header, dict):
        raise ValueError("Header must be a JSON object")
    expected = header.get("payload_len", len(payload))
    if expected != len(payload):
        raise ValueError(
            f"payload_len mismatch expected={expected}, actual={len(payload)}"
        )
    return header, payload


def mod_inverse(a: int, p: int) -> int:
    return pow(a % p, -1, p)


def eval_poly(coeffs: List[int], x: int, p: int) -> int:
    val = 0
    power = 1
    for c in coeffs:
        val = (val + c * power) % p
        power = (power * x) % p
    return val


def split_secret(secret: bytes, k: int, n: int, p: int = 257) -> Dict[int, List[int]]:
    """
    Byte-wise Shamir splitting.
    Returns dict: share_index -> [y_0, y_1, ... y_31], each y in [0, p-1].
    """
    if k < 2 or n < k:
        raise ValueError("Require 2 <= k <= n")
    shares = {x: [] for x in range(1, n + 1)}
    for b in secret:
        coeffs = [b] + [secrets.randbelow(p) for _ in range(k - 1)]
        for x in range(1, n + 1):
            y = eval_poly(coeffs, x, p)
            shares[x].append(y)
    return shares


def lagrange_interpolate_at_zero(points: List[Tuple[int, int]], p: int) -> int:
    """
    Given points (x_i, y_i), recover f(0) mod p.
    """
    total = 0
    for i, (x_i, y_i) in enumerate(points):
        num = 1
        den = 1
        for j, (x_j, _) in enumerate(points):
            if i == j:
                continue
            num = (num * (-x_j)) % p
            den = (den * (x_i - x_j)) % p
        l_i = (num * mod_inverse(den, p)) % p
        total = (total + y_i * l_i) % p
    return total


def recover_secret(shares: List[Tuple[int, List[int]]], p: int = 257) -> bytes:
    if not shares:
        raise ValueError("No shares provided")
    byte_len = len(shares[0][1])
    secret_vals = []
    for b_idx in range(byte_len):
        points = [(x, y_list[b_idx]) for x, y_list in shares]
        val = lagrange_interpolate_at_zero(points, p)
        if val > 255:
            raise ValueError("Recovered byte out of range")
        secret_vals.append(val)
    return bytes(secret_vals)


def encode_share_values(y_vals: List[int]) -> bytes:
    out = bytearray()
    for y in y_vals:
        out.extend(struct.pack(">H", y))
    return bytes(out)


def decode_share_values(data: bytes, expected_len: int = 32) -> List[int]:
    if len(data) != expected_len * 2:
        raise ValueError(f"Invalid share byte length: {len(data)}")
    return [struct.unpack(">H", data[i : i + 2])[0] for i in range(0, len(data), 2)]


class BloomFilter:
    def __init__(self, size_bytes: int = BF_BYTES, k_hashes: int = BF_HASHES):
        self.size_bytes = size_bytes
        self.size_bits = size_bytes * 8
        self.k_hashes = k_hashes
        self.bits = bytearray(size_bytes)

    def _indexes(self, item: bytes) -> List[int]:
        idxs = []
        for i in range(self.k_hashes):
            digest = hashlib.sha256(i.to_bytes(1, "big") + item).digest()
            idxs.append(int.from_bytes(digest, "big") % self.size_bits)
        return idxs

    def add(self, item: bytes) -> None:
        for idx in self._indexes(item):
            b = idx // 8
            offset = idx % 8
            self.bits[b] |= 1 << offset

    def to_bytes(self) -> bytes:
        return bytes(self.bits)

    @classmethod
    def from_bytes(cls, data: bytes, k_hashes: int = BF_HASHES) -> "BloomFilter":
        bf = cls(size_bytes=len(data), k_hashes=k_hashes)
        bf.bits[:] = data
        return bf

    def or_with(self, other: "BloomFilter") -> None:
        if self.size_bytes != other.size_bytes:
            raise ValueError("Bloom filter sizes differ")
        for i in range(self.size_bytes):
            self.bits[i] |= other.bits[i]

    def count_set_bits(self) -> int:
        return sum(BIT_COUNT[b] for b in self.bits)


@dataclass
class OwnEpoch:
    created_at: float
    ephid: bytes
    eph_hash: str
    shares: Dict[int, List[int]]
    dh_priv: int
    dh_pub: int
    next_share_idx: int = 1
    next_send_time: float = field(default_factory=time.time)
    finished: bool = False


@dataclass
class ReceivedEph:
    sender: str
    eph_hash: str
    k: int
    n: int
    sender_pub: int
    first_seen: float
    local_priv: int
    shares: Dict[int, List[int]] = field(default_factory=dict)
    reconstructed: bool = False


class DimyNode:
    def __init__(
        self,
        t: int,
        k: int,
        n: int,
        p_drop: int,
        server_ip: str,
        server_port: int,
        node_id: str,
        udp_port: int = 50000,
        auto_positive_after: Optional[int] = None,
    ) -> None:
        self.t = t
        self.k = k
        self.n = n
        self.p_drop = p_drop
        self.server_ip = server_ip
        self.server_port = server_port
        self.node_id = node_id
        self.udp_port = udp_port
        self.auto_positive_after = auto_positive_after

        self.stop_event = threading.Event()
        self.start_time = time.time()

        # Use one stable DH keypair per node runtime to keep EncID derivation
        # symmetric across peers despite asynchronous EphID reconstruction times.
        self.node_dh_priv = secrets.randbelow(DH_P - 3) + 2
        self.node_dh_pub = pow(DH_G, self.node_dh_priv, DH_P)

        self.state_lock = threading.Lock()
        self.own_epochs: List[OwnEpoch] = []
        self.received: Dict[Tuple[str, str], ReceivedEph] = {}
        self.reconstructed_keys = set()

        self.dbf_lock = threading.Lock()
        self.dbfs: List[Tuple[float, BloomFilter]] = [(time.time(), BloomFilter())]
        self.last_qbf_time = 0.0
        self.uploaded_cbf = False
        self.at_risk_qbfs: List[bytes] = []

        self.udp_send_sock = self._create_udp_send_socket()
        self.udp_recv_sock = self._create_udp_recv_socket()

    def _create_udp_send_socket(self) -> socket.socket:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        return sock

    def _create_udp_recv_socket(self) -> socket.socket:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except (AttributeError, OSError):
            pass
        sock.bind(("", self.udp_port))
        sock.settimeout(1.0)
        return sock

    def _current_local_key(self) -> Tuple[int, int]:
        return self.node_dh_priv, self.node_dh_pub

    def _generate_new_epoch_locked(self) -> OwnEpoch:
        ephid = secrets.token_bytes(32)
        eph_hash = sha256_hex(ephid)
        shares = split_secret(ephid, self.k, self.n)
        epoch = OwnEpoch(
            created_at=time.time(),
            ephid=ephid,
            eph_hash=eph_hash,
            shares=shares,
            dh_priv=self.node_dh_priv,
            dh_pub=self.node_dh_pub,
            next_share_idx=1,
            next_send_time=time.time(),
            finished=False,
        )
        self.own_epochs.append(epoch)
        # Keep recent epochs only.
        cutoff = time.time() - max(self.t * 3, 120)
        self.own_epochs = [e for e in self.own_epochs if e.created_at >= cutoff]
        return epoch

    def _generate_new_epoch(self) -> None:
        with self.state_lock:
            epoch = self._generate_new_epoch_locked()
        log(
            self.node_id,
            f"Task1/2 EphID generated hash={epoch.eph_hash[:12]} "
            f"shares={self.n} k={self.k}",
        )

    def _broadcast_share(self, epoch: OwnEpoch, share_idx: int) -> None:
        y_vals = epoch.shares[share_idx]
        payload_b64 = base64.b64encode(encode_share_values(y_vals)).decode("ascii")
        msg = {
            "type": "SHARE",
            "ver": 1,
            "sender": self.node_id,
            "eph_hash": epoch.eph_hash,
            "share_index": share_idx,
            "k": self.k,
            "n": self.n,
            "pubkey": format(epoch.dh_pub, "x"),
            "share_data": payload_b64,
            "ts": int(time.time()),
        }
        data = json.dumps(msg, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        self.udp_send_sock.sendto(data, ("255.255.255.255", self.udp_port))
        log(
            self.node_id,
            f"Task3 Sent share idx={share_idx}/{self.n} eph={epoch.eph_hash[:10]}",
        )

    def _handle_share_message(self, data: bytes, addr: Tuple[str, int]) -> None:
        try:
            msg = json.loads(data.decode("utf-8"))
        except Exception:
            return

        if msg.get("type") != "SHARE":
            return

        sender = str(msg.get("sender", ""))
        if not sender or sender == self.node_id:
            return

        # Task 3a: drop mechanism
        if secrets.randbelow(100) < self.p_drop:
            log(
                self.node_id,
                f"Task3a Dropped share from={sender} eph={str(msg.get('eph_hash',''))[:10]}",
            )
            return

        eph_hash = str(msg.get("eph_hash", ""))
        share_idx = int(msg.get("share_index", 0))
        k = int(msg.get("k", 0))
        n = int(msg.get("n", 0))
        pub_hex = str(msg.get("pubkey", ""))
        share_b64 = str(msg.get("share_data", ""))

        if not eph_hash or share_idx <= 0 or k <= 0 or n <= 0 or not pub_hex:
            return

        try:
            sender_pub = int(pub_hex, 16)
            share_bytes = base64.b64decode(share_b64.encode("ascii"))
            y_vals = decode_share_values(share_bytes, expected_len=32)
        except Exception:
            return

        local_priv, _ = self._current_local_key()

        key = (sender, eph_hash)
        should_reconstruct = False
        with self.state_lock:
            if key not in self.received:
                self.received[key] = ReceivedEph(
                    sender=sender,
                    eph_hash=eph_hash,
                    k=k,
                    n=n,
                    sender_pub=sender_pub,
                    first_seen=time.time(),
                    local_priv=local_priv,
                )
            rec = self.received[key]
            # Keep the first local private key seen for this EphID.
            if share_idx not in rec.shares:
                rec.shares[share_idx] = y_vals
                log(
                    self.node_id,
                    f"Task3/4 Received share from={sender} eph={eph_hash[:10]} "
                    f"count={len(rec.shares)}/{rec.k}",
                )
            if (not rec.reconstructed) and len(rec.shares) >= rec.k:
                rec.reconstructed = True
                should_reconstruct = True

        if should_reconstruct:
            self._reconstruct_and_process(rec)

        # Cleanup stale entries
        self._prune_received()

        _ = addr  # kept for future debug usage

    def _reconstruct_and_process(self, rec: ReceivedEph) -> None:
        shares_subset = sorted(rec.shares.items())[: rec.k]
        try:
            ephid = recover_secret(shares_subset)
        except Exception as exc:
            log(
                self.node_id,
                f"Task4 Reconstruction failed sender={rec.sender} err={exc}",
            )
            return

        valid = sha256_hex(ephid) == rec.eph_hash
        if not valid:
            log(
                self.node_id,
                f"Task4 Verification failed sender={rec.sender} eph={rec.eph_hash[:10]}",
            )
            return

        log(
            self.node_id,
            f"Task4 Reconstruction OK sender={rec.sender} eph={rec.eph_hash[:10]}",
        )

        key = (rec.sender, rec.eph_hash)
        with self.state_lock:
            if key in self.reconstructed_keys:
                return
            self.reconstructed_keys.add(key)

        # Task 5: Diffie-Hellman encounter ID
        shared = pow(rec.sender_pub, rec.local_priv, DH_P)
        shared_bytes = shared.to_bytes((shared.bit_length() + 7) // 8, "big")
        encid = hashlib.sha256(shared_bytes).digest()
        encid_hex = encid.hex()
        log(
            self.node_id,
            f"Task5 EncID generated with {rec.sender}: {encid_hex[:16]}",
        )

        # Task 6: Insert EncID to DBF and delete local EncID reference
        self._insert_encid_to_dbf(encid)

    def _insert_encid_to_dbf(self, encid: bytes) -> None:
        with self.dbf_lock:
            _, current_dbf = self.dbfs[-1]
            current_dbf.add(encid)
            bits = current_dbf.count_set_bits()
        log(self.node_id, f"Task6/7 EncID inserted into DBF, set_bits={bits}")

    def _combine_dbfs(self) -> bytes:
        combined = BloomFilter()
        with self.dbf_lock:
            for _, dbf in self.dbfs:
                combined.or_with(dbf)
        return combined.to_bytes()

    def _upload_cbf(self) -> None:
        if self.uploaded_cbf:
            log(self.node_id, "CBF already uploaded; skipping.")
            return

        cbf = self._combine_dbfs()
        header = {
            "op": "UPLOAD_CBF",
            "node_id": self.node_id,
            "ts": int(time.time()),
            "ver": PROTOCOL_VERSION,
        }
        try:
            resp_h, _ = self._send_server_request(header, cbf)
            if resp_h.get("op") == "ACK" and resp_h.get("status") == "stored":
                self.uploaded_cbf = True
                log(self.node_id, "Task9 CBF upload successful. QBF generation stopped.")
            else:
                log(self.node_id, f"Task9 CBF upload failed: {resp_h}")
        except Exception as exc:
            log(self.node_id, f"Task9 CBF upload error: {exc}")

    def _query_qbf(self, qbf: bytes) -> None:
        header = {
            "op": "QUERY_QBF",
            "node_id": self.node_id,
            "ts": int(time.time()),
            "ver": PROTOCOL_VERSION,
        }
        try:
            resp_h, _ = self._send_server_request(header, qbf)
            if resp_h.get("op") != "RESULT":
                log(self.node_id, f"Task10 Invalid query response: {resp_h}")
                return
            match = str(resp_h.get("match", "not_matched"))
            log(self.node_id, f"Task10 Risk analysis result: {match}")
            if match == "matched":
                self.at_risk_qbfs.append(qbf)
                log(
                    self.node_id,
                    f"QBF retained for manual tracing, retained={len(self.at_risk_qbfs)}",
                )
        except Exception as exc:
            log(self.node_id, f"Task10 QBF query error: {exc}")

    def _send_server_request(
        self, header: Dict, payload: bytes
    ) -> Tuple[Dict, bytes]:
        with socket.create_connection((self.server_ip, self.server_port), timeout=8) as sock:
            send_frame(sock, header, payload)
            parsed = recv_frame(sock)
            if parsed is None:
                raise ConnectionError("No response from server")
            return parsed

    def _prune_dbfs(self) -> None:
        ttl = self.t * 6 * 6  # seconds
        now = time.time()
        with self.dbf_lock:
            before = len(self.dbfs)
            self.dbfs = [(ts, bf) for ts, bf in self.dbfs if now - ts <= ttl]
            # Max 6 DBFs by specification.
            if len(self.dbfs) > 6:
                self.dbfs = self.dbfs[-6:]
            if not self.dbfs:
                self.dbfs.append((now, BloomFilter()))
            after = len(self.dbfs)
        if after != before:
            log(self.node_id, f"Task7 Pruned DBFs: {before} -> {after}")

    def _rotate_dbf_if_needed(self) -> None:
        period = self.t * 6
        now = time.time()
        with self.dbf_lock:
            current_ts, _ = self.dbfs[-1]
            if now - current_ts >= period:
                self.dbfs.append((now, BloomFilter()))
                if len(self.dbfs) > 6:
                    self.dbfs = self.dbfs[-6:]
                log(self.node_id, f"Task7 New DBF created, total_dbf={len(self.dbfs)}")

    def _maybe_build_qbf(self) -> None:
        if self.uploaded_cbf:
            return
        interval = self.t * 6 * 6  # every Dt minutes == t*36 seconds
        now = time.time()
        if now - self.last_qbf_time < interval:
            return
        self.last_qbf_time = now
        qbf = self._combine_dbfs()
        log(self.node_id, "Task8 QBF built from current DBFs")
        self._query_qbf(qbf)

    def _prune_received(self) -> None:
        # Keep only recent partial records to avoid unbounded growth.
        cutoff = time.time() - max(self.t * 6 * 2, 120)
        with self.state_lock:
            keys = [k for k, v in self.received.items() if v.first_seen < cutoff]
            for k in keys:
                del self.received[k]

    def ephid_thread(self) -> None:
        self._generate_new_epoch()
        while not self.stop_event.is_set():
            if self.stop_event.wait(self.t):
                break
            self._generate_new_epoch()

    def broadcaster_thread(self) -> None:
        while not self.stop_event.is_set():
            now = time.time()
            did_send = False
            with self.state_lock:
                # Send one due share each loop to keep timing stable.
                for epoch in self.own_epochs:
                    if epoch.finished:
                        continue
                    if now >= epoch.next_send_time and epoch.next_share_idx <= self.n:
                        idx = epoch.next_share_idx
                        epoch.next_share_idx += 1
                        epoch.next_send_time = now + 3
                        if epoch.next_share_idx > self.n:
                            epoch.finished = True
                        target_epoch = epoch
                        target_idx = idx
                        did_send = True
                        break
                else:
                    target_epoch = None
                    target_idx = 0
            if did_send and target_epoch is not None:
                try:
                    self._broadcast_share(target_epoch, target_idx)
                except Exception as exc:
                    log(self.node_id, f"Broadcast error: {exc}")
            time.sleep(0.2)

    def receiver_thread(self) -> None:
        while not self.stop_event.is_set():
            try:
                data, addr = self.udp_recv_sock.recvfrom(UDP_RECV_BUFFER)
                self._handle_share_message(data, addr)
            except socket.timeout:
                continue
            except OSError:
                if self.stop_event.is_set():
                    return
            except Exception as exc:
                log(self.node_id, f"Receiver error: {exc}")

    def dbf_thread(self) -> None:
        while not self.stop_event.is_set():
            self._rotate_dbf_if_needed()
            self._prune_dbfs()
            self._maybe_build_qbf()
            time.sleep(1.0)

    def command_thread(self) -> None:
        log(
            self.node_id,
            "Commands: 'upload', 'query', 'status', 'quit'.",
        )
        while not self.stop_event.is_set():
            try:
                cmd = input().strip().lower()
            except EOFError:
                return
            except Exception:
                return
            if cmd == "upload":
                self._upload_cbf()
            elif cmd == "query":
                qbf = self._combine_dbfs()
                log(self.node_id, "Manual query: sending QBF to backend...")
                self._query_qbf(qbf)
            elif cmd == "status":
                with self.dbf_lock:
                    bits = [dbf.count_set_bits() for _, dbf in self.dbfs]
                log(self.node_id, f"DBF count={len(bits)} set_bits={bits}")
            elif cmd == "quit":
                self.stop_event.set()
                return
            elif cmd:
                log(self.node_id, f"Unknown command: {cmd}")

    def auto_positive_thread(self) -> None:
        if self.auto_positive_after is None:
            return
        while not self.stop_event.is_set():
            elapsed = time.time() - self.start_time
            if elapsed >= self.auto_positive_after:
                log(
                    self.node_id,
                    f"Auto-positive triggered at {int(elapsed)}s, uploading CBF...",
                )
                self._upload_cbf()
                return
            time.sleep(1.0)

    def run(self) -> None:
        log(
            self.node_id,
            f"Starting node: t={self.t}, k={self.k}, n={self.n}, p={self.p_drop}, "
            f"server={self.server_ip}:{self.server_port}, udp={self.udp_port}",
        )
        log(self.node_id, f"DH public key prefix={format(self.node_dh_pub, 'x')[:16]}")

        threads = [
            threading.Thread(target=self.ephid_thread, daemon=True),
            threading.Thread(target=self.broadcaster_thread, daemon=True),
            threading.Thread(target=self.receiver_thread, daemon=True),
            threading.Thread(target=self.dbf_thread, daemon=True),
            threading.Thread(target=self.command_thread, daemon=True),
            threading.Thread(target=self.auto_positive_thread, daemon=True),
        ]
        for t in threads:
            t.start()

        try:
            while not self.stop_event.is_set():
                time.sleep(0.5)
        except KeyboardInterrupt:
            log(self.node_id, "Interrupted, shutting down...")
            self.stop_event.set()
        finally:
            try:
                self.udp_recv_sock.close()
            except Exception:
                pass
            try:
                self.udp_send_sock.close()
            except Exception:
                pass
            log(self.node_id, "Stopped.")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="DIMY frontend node")
    parser.add_argument("t", type=int, help="EphID period in seconds")
    parser.add_argument("k", type=int, help="Shamir threshold")
    parser.add_argument("n", type=int, help="Shamir total shares")
    parser.add_argument("p", type=int, help="Drop probability percentage")
    parser.add_argument("server_ip", type=str, help="Backend server IP")
    parser.add_argument("server_port", type=int, help="Backend server TCP port")
    parser.add_argument("--node-id", type=str, default=None)
    parser.add_argument("--udp-port", type=int, default=50000)
    parser.add_argument(
        "--auto-positive-after",
        type=int,
        default=None,
        help="Auto upload CBF after N seconds",
    )
    return parser.parse_args()


def validate_args(args: argparse.Namespace) -> None:
    valid_t = {15, 18, 21, 24, 27, 30}
    if args.t not in valid_t:
        raise ValueError(f"t must be in {sorted(valid_t)}")
    if args.k < 3:
        raise ValueError("k must be >= 3")
    if args.n < 5:
        raise ValueError("n must be >= 5")
    if args.k >= args.n:
        raise ValueError("Require k < n")
    valid_p = {30, 40, 50, 60, 70}
    if args.p not in valid_p:
        raise ValueError(f"p must be in {sorted(valid_p)}")


def main() -> None:
    args = parse_args()
    validate_args(args)
    node_id = args.node_id or f"Node-{secrets.randbelow(9000) + 1000}"
    node = DimyNode(
        t=args.t,
        k=args.k,
        n=args.n,
        p_drop=args.p,
        server_ip=args.server_ip,
        server_port=args.server_port,
        node_id=node_id,
        udp_port=args.udp_port,
        auto_positive_after=args.auto_positive_after,
    )
    node.run()


if __name__ == "__main__":
    main()
