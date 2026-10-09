# Secure Edge-Cloud IoT Sensor Pipeline

An ESP8266 (NodeMCU) with a DHT11 sensor sends temperature and humidity readings
over encrypted WiFi (HTTPS) through a gateway to parallel edge and cloud
processing. Every reading is signed with the device's own **ECDSA private
key** and re-verified at each hop, so each stage can prove the data came from
a known, non-revoked device, wasn't altered, isn't a replay and isn't stale.
When something goes wrong, the logs say **where**, and the original reading is
recovered from a signed backup.

**Contents:** [The problem](#the-problem) · [Architecture](#architecture) ·
[Loopholes closed](#loopholes-closed) · [Remaining limitations](#remaining-limitations) ·
[Dashboard](#dashboard) · [Running the demo](#running-the-demo) · [Run guide](RUNNING.md) ·
[Results](#results) · [Repository layout](#repository-layout)

---

## The problem

Sensor data crosses several hops (device → WiFi → gateway → processing) and
can be attacked at any of them:

| Attack | What the attacker does |
|---|---|
| Packet corruption | Alters bytes of a reading in transit |
| Packet injection | Sends fake readings that never came from a sensor |
| Replay | Captures a genuine reading and resends it later |
| Duplication | Sends the same reading twice |
| Delay | Holds a reading back and delivers it after newer ones, or much later |
| Packet dropping | Stops readings arriving (or the device goes out of range) |
| Gateway compromise | A compromised gateway changes data after checking it |
| Processing-node compromise | An edge or cloud node returns wrong results |
| Eavesdropping / flooding | Reads readings off the network, or floods the gateway |

The original design also had two structural gaps:

1. **No backups.** If processed results were wrong, the original reading was gone.
2. **Unknown tamper location.** A bad result showed *that* something was
   wrong, but not *which hop* was responsible.

## Architecture

```
 ESP8266 + DHT11              Gateway (x2)              Fork point
┌──────────────┐  WiFi   ┌──────────────────┐     ┌───────────────────────┐
│ read sensor  │ ──────▶ │ device known and │ ──▶ │ verify gateway sig    │
│ counter++    │  HTTPS  │   not revoked?   │     │ RE-verify ECDSA sig   │
│ (flash)      │ (pinned │ ECDSA sig valid? │     │   (end to end)        │
│ ECDSA-sign   │   key)  │ timestamp ±60 s? │     │ check counter         │
└──────────────┘         │ counter fresh?   │     │ assign chunk_id       │
                         │ add gateway sig  │     └──────────┬────────────┘
                         └──────────────────┘                │ same chunk_id
                                                ┌────────────┴────────────┐
                                                ▼                         ▼
                                      ┌──────────────────┐     ┌────────────────────┐
                                      │ Edge             │     │ Cloud              │
                                      │ process          │     │ store raw reading  │
                                      │                  │     │ + device signature │
                                      │                  │     │ THEN process       │
                                      └────────┬─────────┘     └─────────┬──────────┘
                                               └────────────┬────────────┘
                                                            ▼
                                             ┌─────────────────────────────┐
                                             │ Validation                  │
                                             │ edge ≈ cloud (± 2%)?        │
                                             │  yes → final storage        │
                                             │  no  → fetch backup, VERIFY │
                                             │        its signature:       │
                                             │        ok → recompute, store│
                                             │        bad → quarantine     │
                                             │ + anomaly flag (3σ)         │
                                             └─────────────────────────────┘
```

**The integrity chain, step by step:**

1. **The device signs.** The firmware reads the DHT11 every 2 s, increments a
   counter saved in flash, and signs `{sensor_id, timestamp, counter, data}`
   with **ECDSA P-256** using a private key that exists only on the device. It
   sends over **HTTPS**, pinning the gateway's public key, so nothing on the
   network can read the reading or impersonate the gateway.
2. **The gateway verifies and countersigns.** It checks the device is known and
   not revoked, verifies the signature with the device's **public** key,
   requires the timestamp to be within ±60 s, and requires the counter to be
   higher than any seen before. It then adds its own `gateway_signature`.
3. **The fork verifies the full chain.** It checks the gateway's signature
   **and** independently re-checks the device's. Gateways hold only public
   keys, so even a fully compromised gateway can't forge a device signature.
4. **Edge and cloud process in parallel.** Both compute the same thermal-comfort
   assessment (heat index, dew point, comfort band). The cloud first stores the
   raw reading **together with the device's signature** as a backup.
5. **Validation compares and recovers.** Results must agree within 2%. On a
   mismatch, the backup's signature is re-verified before it's trusted: if it
   holds, the result is recomputed from it and stored (marked recovered); if
   not, the chunk is quarantined.

The sensor is **real hardware**: a NodeMCU ESP8266 running the firmware in
`firmware/` (the same source also builds for an ESP32). The attack simulator
only crafts attack traffic to test the defences.

**Tamper location.** Every rejection is recorded, with the hop where it was
caught, in an event log whose entries are **hash-chained with a secret key**,
so the log itself can't be edited undetected:

| `hop` | Caught there |
|---|---|
| `sensor-gateway` | corruption, injection, replay, duplication, delay, stale timestamp, unknown or revoked device, flooding (`rate_limited`) |
| `gateway-fork` | gateway altered data after verifying it; forged gateway signature |
| `fork-edge` / `fork-cloud` | malformed data reaching processing; duplicate `chunk_id`; quarantine |
| `edge-cloud-validation` | edge and cloud disagree (`validation_failed` → `recovered` or `quarantined`); anomalous readings |

## Loopholes closed

| Loophole | How it's closed | Where |
|---|---|---|
| **Data altered in transit** | **End-to-end signature chain.** Each device signs with its own ECDSA key; the fork re-verifies the original device signature, so the reading must be byte-for-byte what the device sent. | `firmware/src/main.cpp`, `gateway/`, `fork/` |
| **Compromised gateway forging data** | **Asymmetric signatures.** Servers hold only device *public* keys, which can verify but never sign. Altered data is caught at the fork as `gateway-tampered-after-verification`. | `shared/crypto_utils.py`, `fork/` |
| **Eavesdropping, gateway impersonation** | **TLS (HTTPS) with the gateway's key pinned in the firmware.** Plain HTTP is no longer reachable from the LAN. | `firmware/`, `docker/nginx.conf` |
| **Replay, duplication, reordering** | **Monotonic counter persisted in the device's flash** before each send; gateway and fork reject any counter ≤ the last one, and both persist their counters across restarts. | `firmware/`, `shared/service_utils.py` |
| **Delayed delivery / lost counter state** | **Timestamp window:** readings more than 60 s from the server's clock are rejected (`stale_timestamp`). | `gateway/` |
| **Compromised processing node** | **Tolerance-based dual-path validation.** Edge and cloud must agree within 2%. | `validation/` |
| **No backups / untrusted backups** | **Signed backups, verified before use.** The cloud stores each raw reading with its device signature before processing; recovery re-verifies it, recomputes the result if it holds, and **quarantines** it if not. | `cloud/`, `validation/` |
| **Unknown tamper location; editable logs** | Every rejection names its hop, in a **keyed hash-chained event log**; the dashboard's *Verify Integrity* recomputes the chain. | `shared/events.py` |
| **A leaked or lost device** | **Revocation** (`scripts/revoke_sensor.py`), effective immediately at every stage without a restart; **key rotation** (`scripts/rotate-keys.ps1`). | `shared/config.py`, `scripts/` |
| **Flooding** | **Per-client rate limiting** on every LAN-facing port (nginx, and in-app on the fallback port). | `docker/nginx.conf`, `gateway/` |
| **Committed dev keys used live** | Real keys, certificates and secrets are generated into gitignored files; the device's private key is written only to the firmware, never to a server. | `scripts/generate_secrets.py` |
| **Implausible readings** | A separate anomaly flag: more than 3σ from the sensor's last 20 readings (σ floored at 1.0 for the DHT11's whole-number readings); history persists across restarts. | `validation/` |

## Remaining limitations

These can't be closed in software within this project:

- **The ESP8266 can't encrypt its flash.** Someone with physical access to a
  board can read its private key. The damage is limited to that one device,
  which can be revoked; fully closing it needs a board with secure boot and
  flash encryption (e.g. ESP32) or a hardware secure element (e.g. ATECC608).
- **Key rotation isn't automatic.** `rotate-keys.ps1` replaces every key in one
  step but needs the board on USB. Rotating keys over the air would need an
  authenticated key-update protocol and OTA firmware updates.
- **One host is a single point of failure.** The two gateways guard against a
  crashed instance, not a crashed machine; that needs a second host.
- **NTP time isn't authenticated.** An attacker who controls the network could
  feed the board a wrong time; its readings would then be *rejected* by the
  timestamp check (a denial of service), but not accepted when they shouldn't be.
- **The certificate is pinned by SHA-1 fingerprint.** The ESP8266 core's
  public-key pinning rejects valid ECDSA handshakes (TLS error 27), so the board
  pins the gateway certificate's fingerprint instead. No practical attack on
  this use of SHA-1 is known, but a SHA-256 pin would be better.
- **Dev material is committed for tests.** `gateway/keystore.json`,
  `tests/dev_sensor_keys.json` and `docker/certs/dev/` are public; a live
  setup must run `rotate-keys.ps1` (the run guide says so).

## Dashboard

A web dashboard at **http://localhost:8080** shows the pipeline live:

| Page | Shows |
|---|---|
| Main Overview | Board online/offline, validated-reading count, latest reading (with its age) and comfort level, live chart of the latest session, and the checks each result passed. A device menu switches between the physical board and the virtual board; **Auto** shows whichever is live |
| Threat Simulator | One button per attack (9), or Run All; each shows whether it was caught, with a feed of tamper events and their hop |
| Integrity Chain | The four stages with live counts: accepted, rejected, mismatches, verified recoveries, quarantined, anomalies |
| Event Ledger | Every event, filterable and searchable; **Verify Integrity** checks the hash chain; export as JSON |
| System Health | Each container's health and response time, and a **Benchmark** button |

It's published on localhost only, and its action buttons require a custom
header, so neither other devices nor other websites can trigger them.

## Running the demo

See **[RUNNING.md](RUNNING.md)** for the step-by-step guide. In short, from
`C:\iot-sensor-pipeline` in PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\rotate-keys.ps1   # once: real keys, board re-flashed (board on USB)
powershell -ExecutionPolicy Bypass -File scripts\start-demo.ps1    # every time: starts everything, opens the dashboard
```

Then, from `docker\`: `docker compose run --rm attack-simulator` (attacks 1–8)
and `docker compose run --rm attack-simulator python -m tests.benchmark`.

**No board?** `start-demo.ps1 -Virtual` also starts a virtual sensor board
(`tests/virtual_board.py`, identity `esp32-002`) that signs and sends readings
over HTTPS exactly like the firmware, so the dashboard is live without hardware.

In VS Code, every step is a task: **Ctrl+Shift+P → Tasks: Run Task**.

## Results

| What | Result |
|---|---|
| Unit tests | 121 passing (`python -m pytest`), plus CI on every push |
| Attack simulator against the running stack | 8/8 detected at the expected hop; packet dropping tolerated |
| Benchmark (100 genuine readings, 10 runs × 8 attacks) | **100% detection, 0% false positives, F1 1.000**; end-to-end latency p50 112 ms, p95 132 ms, p99 135 ms ([`docs/benchmark-results.json`](docs/benchmark-results.json)) |
| TLS, certificate pinning, LAN exposure | HTTPS accepted on 8443 and 8011; clients without the pinned certificate refused; plain HTTP unreachable from the LAN |
| Rate limiting | A 40-request burst: first 20 served, the rest `429` |
| Revocation | Revoked device refused (`403`) from the next request, restored likewise, no restart |
| Event log | Hash chain verified intact; edits, deletions and re-hashing without the key detected (tests) |
| Real hardware | NodeMCU ESP8266 + DHT11 with the ECDSA + TLS firmware: readings accepted end to end over HTTPS (`HTTP 200`), ECDSA signing 127–128 ms per reading at 160 MHz; 41.1% flash, 37.9% RAM. Long-run figures: `tests/soak_report.py` |

## Repository layout

| Folder | What's in it |
|---|---|
| `firmware/` | C++ firmware for NodeMCU ESP8266 (default) or ESP32: sensor reading, flash-persisted counter, ECDSA signing, HTTPS with certificate pinning, gateway fallback |
| `gateway/` | Gateway service; `keystore.json` (dev public keys) |
| `fork/` | Fork point: full-chain verification, fan-out, calls validation |
| `edge/`, `cloud/` | Processing nodes; the cloud also holds the signed backup store and quarantine |
| `validation/` | Edge-vs-cloud comparison, verified recovery, anomaly check |
| `dashboard/` | Web dashboard: FastAPI backend and the page (`static/`) |
| `shared/` | Envelope format, config, crypto, verification, processing, event log |
| `tests/` | Unit tests, `attack_simulator.py`, `benchmark.py`, `virtual_board.py`, `soak_report.py`, dev test keys |
| `scripts/` | `start-demo.ps1`, `rotate-keys.ps1`, `generate_secrets.py`, `revoke_sensor.py` |
| `docker/` | Dockerfile, `docker-compose.yml`, nginx (TLS + rate limiting), dev certificates, [Docker guide](docker/README.md) |
| `docs/` | [Service reference](docs/SERVICES.md), [SRS](docs/SRS.docx), research paper and patent drafts, benchmark results |
