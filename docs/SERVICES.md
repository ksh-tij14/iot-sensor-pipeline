# Service reference

Details of each component: settings, endpoints, and every rejection reason.
For the overview, start with the [main README](../README.md).

## Design decisions

- **Device signatures: ECDSA P-256 over SHA-256.** Each device holds its own
  private key; servers hold only public keys (`gateway/keystore.json` format:
  `{"sensor_id": {"public_key": "04…", "revoked": false}}`). A compromised
  server can verify readings but not forge them. Signatures travel as raw
  `r||s` in hex (128 characters).
- **Gateway signature: HMAC-SHA256** with a key shared by gateway and fork
  (both server-side), covering the whole chunk including the device signature.
- **Freshness:** a per-device `counter`, persisted in the device's flash before
  each send (Preferences API: NVS on ESP32, LittleFS on ESP8266), plus a
  ±60 s timestamp window (`MAX_CLOCK_SKEW_SECONDS`).
- **Transport:** HTTPS. The ESP8266 pins the gateway's certificate (SHA-1 fingerprint); the ESP32
  build checks the certificate.
- **Validation:** edge and cloud "match" if they agree within 2% (relative).
- **Keys and certificates** come from `scripts/generate_secrets.py`; the
  committed ones are dev material for tests.

## The envelope

```
SignedChunk(sensor_id, timestamp, counter, data, sensor_signature, gateway_signature=None)
```

The device signs `signing_bytes()`: compact JSON, keys sorted, signatures
excluded. The firmware must produce **byte-identical** output, so `timestamp`
is integer milliseconds and `data` values are integers in hundredths
(`temp_centi_c`, `humidity_centi_pct`). `test_signing_bytes_are_canonical` in
`tests/test_shared.py` pins the exact format. The gateway signs
`gateway_signing_bytes()`: every field except `gateway_signature`.

## Flashing a sensor

Normally `scripts/rotate-keys.ps1` does all of this. Manually:

1. `python scripts/generate_secrets.py` writes `firmware/include/secrets.h`
   (WiFi details kept; private key and the gateway's TLS key/cert filled in).
2. At the top of `firmware/src/main.cpp`, set `SENSOR_ID`, `GATEWAY_URL`
   (`https://<PC IP>:8443/ingest`) and `GATEWAY_URL_FALLBACK` (`:8011`).
3. `pio run -t upload` from `firmware/` (NodeMCU ESP8266 by default; `-e esp32dev` for an ESP32).

On first boot the ID and private key are copied into flash; later boots read
only from there. To store a new key, flash once with `FORCE_REPROVISION 1`,
then again with `0`. Wire the DHT11 data pin to GPIO4: **D2** on a NodeMCU,
**D4** on an ESP32 DevKit. The firmware corrects a DHT11 quirk where some
variants make the Adafruit library report negative temperatures.

Every `CHUNK_INTERVAL_SECONDS` (5) the firmware reads the sensor and:

- skips the interval (no counter change) if the read fails, WiFi is down, the
  clock isn't synced, or no valid private key is stored;
- otherwise increments the counter and writes it to flash **before** sending;
- signs with ECDSA (BearSSL on ESP8266, mbedTLS on ESP32) and POSTs over HTTPS,
  falling back to `GATEWAY_URL_FALLBACK` only if the primary gives no HTTP response.

## Gateway (`gateway/gateway_service.py`, port 8001; HTTPS 8443 optional)

`POST /ingest`. Checks, in order (rejections are `tamper` events, hop `sensor-gateway`):

| Reason | HTTP |
|---|---|
| `malformed_chunk` (bad JSON, missing field, wrong type, floats in `data`, wrong signature length) | 422 |
| `unknown_sensor` / `bad_sensor_signature` | 401 |
| `revoked_sensor` | 403 |
| `stale_timestamp` (more than 60 s from the server's clock) | 409 |
| `stale_or_replayed_counter` | 409 |
| `rate_limited` (direct HTTPS port only; nginx limits the load-balanced port) | 429 |

The keystore is re-read when it changes, so revocation needs no restart.
Counters are in memory unless `GATEWAY_COUNTER_DB` names a SQLite file (Docker
sets it, shared by both instances, updated atomically). With
`GATEWAY_TLS_PORT/CERT/KEY` set it also serves HTTPS (gateway-2's fallback port).
If the fork is unreachable it returns 502 and logs `forward_failed`.

## Fork point (`fork/fork_service.py`, port 8002)

`POST /forward`. For each chunk it:

1. verifies `gateway_signature` (`bad_gateway_signature`, 401);
2. re-verifies the device signature itself; a failure with a valid gateway
   signature means the data changed after the gateway checked it:
   `gateway-tampered-after-verification` (401); `revoked_sensor` (403);
3. rejects replayed counters (persisted with `FORK_COUNTER_DB`);
4. sends `{chunk_id, sensor_id, timestamp, counter, data, sensor_signature}` to
   `CLOUD_URL/process` and `EDGE_URL/process` in parallel, with one random UUID `chunk_id`;
5. sends both results to `VALIDATION_URL/validate`.

## Edge and cloud (ports 8003, 8004)

Both expose `POST /process`, taking `{chunk_id, data, …}` and returning
`{chunk_id, result}`: a thermal-comfort assessment from `shared/processing.py`
(NWS heat index, Magnus dew point, NWS comfort band). Same function on both, so
for the same chunk the results must agree.

The cloud also keeps:

- **Signed backups:** every raw reading with its device signature, stored
  **before** processing (`CLOUD_DB_PATH`). `GET /retrieve/{chunk_id}` returns
  it; callers must verify it. A repeated `chunk_id` is rejected (409 `duplicate_chunk_id`).
- **Final storage:** `POST /forward {chunk_id, result, recovered}`, accepted
  only for chunks it received and never for quarantined ones.
- **Quarantine:** `POST /quarantine {chunk_id, reason}` sets a chunk aside and
  withdraws any stored result; `GET /quarantine` lists them.
- `GET /results/recent` for the dashboard. Old databases are migrated automatically.

## Validation (`validation/validation_service.py`, port 8005)

`POST /validate` with `{chunk_id, sensor_id, cloud_result, edge_result}`.

- **Cloud vs edge:** numeric fields within 2% (relative), labels equal.
  - Match: the result goes to final storage.
  - Mismatch (`validation_failed`): both results are discarded; the backup is
    fetched and its device signature re-verified. Valid → the result is
    recomputed from it and stored with `recovered: true` (`recovered` event).
    Missing, unsigned or invalid → `quarantined`.
- **Anomaly:** each reading against the sensor's last 20 (3σ, σ floored at
  1.0); flagged as `anomaly`, still forwarded. History persists with
  `VALIDATION_STATE_DB`. Results that disagreed never enter the history.

## Event log (`shared/events.py`)

With `EVENT_DB_PATH` set, every service's events go to one SQLite store. Each
entry's `entry_hash` is an HMAC (key `EVENT_LOG_KEY`) over its fields and the
previous entry's hash; writers are serialised so the chain stays linear.
`verify_chain()` reports the first edited, deleted or reordered entry. Old
entries are pruned past 20,000; the oldest remaining one anchors the chain.

## Dashboard (`dashboard/dashboard_service.py`, port 8080)

Serves the page and an API: `GET /api/overview`, `/api/readings`,
`/api/events?kind=all|accepted|validated|tamper|anomaly|recovery|failures`,
`/api/events/verify`, `/api/health`, `/api/attacks`; `POST /api/attacks/{key}`,
`POST /api/attacks` and `POST /api/benchmark` (these need the
`X-Dashboard-Action: 1` header, so other websites can't trigger them).

## Scripts

| Script | Does |
|---|---|
| `scripts/start-demo.ps1 [-FixFirmware]` | Starts Docker and the stack, checks (and fixes) the board's gateway address, opens the dashboard |
| `scripts/rotate-keys.ps1` | New keys and certificate everywhere, board re-flashed, stack restarted |
| `scripts/generate_secrets.py [--dev]` | Generates keys, certificate and secrets (used by `rotate-keys.ps1`) |
| `scripts/revoke_sensor.py <id> [--restore] / --list` | Revokes or restores a device, effective immediately |

## Running without Docker

Start each service in its own terminal, from the repo root:

```bash
python -m cloud.cloud_service
python -m edge.edge_service
python -m validation.validation_service
python -m fork.fork_service
python -m gateway.gateway_service
```

Then `python -m tests.attack_simulator` and `python -m tests.benchmark` run against them.

## Tests

```bash
pip install -r requirements.txt
python -m pytest
```

`tests/attack_simulator.py` and `tests/benchmark.py` aren't collected by
pytest; they need live services. CI (`.github/workflows/ci.yml`) runs the unit
tests, builds the images and runs attacks 1-8 against the Docker stack on every push.
