# infra — local dev services (loopback only)

## Fresh boot

```sh
cp .env.example .env
python infra/scripts/keygen.py --out .env --force   # dev-only secrets, never commit
docker compose up -d                                 # anvil :8545 + mosquitto :1883
docker compose ps
python infra/scripts/keygen.py --help
```

Ports bind `127.0.0.1` only. Anvil chain ID `31337` (`ANVIL_RPC`).
MQTT `MQTT_URL=mqtt://127.0.0.1:1883`; publishers use QoS 1, `retained=false`
(`retain_available false` in `mosquitto/mosquitto.conf`).

## MQTT topics

- Devices publish: `devices/{device_id}/telemetry` (QoS 1, retained=false).
- Broker ACL (`mosquitto/acl.conf`) limits transport to that pattern;
  cryptographic device/topic binding + replay checks land in PG-012 gateway code,
  not in the broker.

## Teardown

```sh
docker compose down
```
