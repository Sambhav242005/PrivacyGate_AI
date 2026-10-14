"""PG-011 simulator entrypoint: publish signed telemetry over MQTT.

QoS 1, retained=false, topic devices/{device_id}/telemetry, max 4096 bytes.
"""
from __future__ import annotations

import argparse
import base64
import json
import sys
import time

from nacl.signing import SigningKey

from simulator.fixtures import (
    DEFAULT_DEVICE_ID,
    DEFAULT_RESOURCE_ID,
    generate_signed,
    make_invalid,
)
from simulator.signing import b64_pubkey, canonical

TOPIC_FMT = "devices/{device_id}/telemetry"
MAX_BYTES = 4096


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="PrivacyGate AI telemetry simulator (PG-011)")
    p.add_argument("--broker", default="127.0.0.1")
    p.add_argument("--port", type=int, default=1883)
    p.add_argument("--device-id", default=DEFAULT_DEVICE_ID)
    p.add_argument("--resource-id", default=DEFAULT_RESOURCE_ID)
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--count", type=int, default=10)
    p.add_argument("--mode", choices=("normal", "anomaly"), default="normal")
    p.add_argument("--invalid", choices=("tamper", "replay", "expired"), default=None)
    p.add_argument("--interval", type=float, default=0.2)
    p.add_argument("--private-key-b64", default=None, help="base64 32-byte Ed25519 seed")
    p.add_argument("--dry-run", action="store_true", help="print payloads, do not connect")
    return p


def load_key(arg: str | None) -> SigningKey:
    if arg:
        return SigningKey(base64.b64decode(arg))
    return SigningKey.generate()


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    key = load_key(args.private_key_b64)
    print(f"device_pubkey_b64={b64_pubkey(key)}", file=sys.stderr)

    msgs = generate_signed(
        args.seed, args.count,
        key, device_id=args.device_id, resource_id=args.resource_id, mode=args.mode,
    )
    if args.invalid:
        msgs = make_invalid(msgs, args.invalid)

    payloads = [canonical(m) for m in msgs]
    for p in payloads:
        if len(p) > MAX_BYTES:
            print(f"oversize payload {len(p)} > {MAX_BYTES}", file=sys.stderr)
            return 2

    if args.dry_run:
        for p in payloads:
            print(p.decode("utf-8"))
        return 0

    import paho.mqtt.client as mqtt  # lazy: dry-run needs no broker dep

    topic = TOPIC_FMT.format(device_id=args.device_id)
    client = mqtt.Client()
    client.connect(args.broker, args.port, keepalive=60)
    client.loop_start()
    try:
        for p in payloads:
            info = client.publish(topic, p, qos=1, retain=False)
            info.wait_for_publish(timeout=10)
            if not info.is_published():
                print("publish failed", file=sys.stderr)
                return 1
            time.sleep(args.interval)
    finally:
        client.loop_stop()
        client.disconnect()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
