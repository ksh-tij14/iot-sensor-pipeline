# Running the pipeline in Docker

Containers on one network (`pipeline`): a load balancer (`gateway-lb`), two
gateways (`gateway-1`, `gateway-2`), then `fork`, `edge`, `cloud` and
`validation`, and a web `dashboard` (http://localhost:8080, localhost only). They find each other by service name (`http://fork:8002` etc.),
set through environment variables in `docker-compose.yml`. The load balancer
serves **HTTPS on 8443** to the LAN (rate-limited), and plain HTTP on 8001 to
this PC only; `gateway-2` is also published over HTTPS on **8011** as a fallback
(see the stretch feature below). Everything else is reachable only inside the
Docker network.

## Bring the stack up

From this `docker/` folder:

```bash
docker compose up --build -d --wait
```

`--wait` returns once every service reports healthy. Then:

```bash
docker compose ps                            # all eight should be "healthy"
docker compose logs -f gateway-1 gateway-2   # follow logs (Ctrl+C to stop)
docker compose down                          # stop; stored data is kept
docker compose down -v                       # stop AND delete stored data
```

- The cloud's SQLite backup store lives in the named volume `cloud-data`, so
  it survives restarts and rebuilds.
- Every service restarts automatically (`unless-stopped`), including after a
  reboot if Docker starts on login.
- Keys, the TLS certificate and secrets come from `docker/.env`, written by
  `scripts/rotate-keys.ps1`. Without it the stack runs on the committed **dev**
  material, which is public: fine for tests, never for a real demo.
- Fork counters (`fork-state`) and validation's anomaly history
  (`validation-state`) persist too, as do the gateways' counters (`gateway-state`)
  and the hash-chained event log (`events`).

## Point the sensor board at the stack

The board needs your **host machine's** LAN IP. The gateway's own startup
message can't show it, because inside a container it only sees the container's
internal address.

- **Windows:** run `ipconfig` and take the **IPv4 Address** under your WiFi
  adapter (e.g. `10.101.78.135`).
- **macOS:** `ipconfig getifaddr en0`
- **Linux:** `hostname -I`

Then set it in `firmware/src/main.cpp` and re-flash:

```cpp
#define GATEWAY_URL "https://10.114.82.135:8443/ingest"
#define GATEWAY_URL_FALLBACK "https://10.114.82.135:8011/ingest"
```

The board must be on the same network as the host, and the host firewall must
allow inbound connections on ports 8443 and 8011. On Windows, set the network
to **Private**; Docker Desktop adds its own firewall rule when it publishes a
port.

## Run the attack simulator against the stack

It runs inside the Docker network, because some attacks target the fork and
validation, which aren't published to the host:

```bash
docker compose run --rm attack-simulator
```

This runs attacks 1-8 (the script-driven ones) and exits non-zero if any fail.
Attack 9, packet dropping, is for the live demo with the real board. The
benchmark runs the same way:

```bash
docker compose run --rm attack-simulator python -m tests.benchmark --genuine 100 --runs 10
```

## Stretch feature: redundant gateways

### What it does

```
                      ┌──────────────────── Docker host ─────────────────────┐
Sensor ─ primary ──▶ │ :8443 gateway-lb (nginx) ─┬─▶ gateway-1 ─┐            │
  │                   │                           └─▶ gateway-2 ─┼─▶ fork ─▶ … │
  └──── fallback ───▶ │ :8011 ────────────────────────▶ gateway-2 ┘            │
                      │          both share /state/counters.db               │
                      └──────────────────────────────────────────────────────┘
```

- **Two gateway instances behind nginx** (`nginx.conf`), round-robin. If one
  instance refuses the connection or doesn't accept it within 1 s, nginx
  retries the request on the other and skips the failed one for 10 s.
- **Firmware fallback:** the board tries `GATEWAY_URL` (the load balancer)
  with a 1.5 s connect timeout. If there is no HTTP response at all (refused,
  unreachable, timed out), it resends the same chunk to `GATEWAY_URL_FALLBACK`.
  Here that's `gateway-2` directly on port 8011, so it also covers the load
  balancer itself failing; in a real deployment it would be a gateway on a
  second machine. An HTTP error such as 401 or 409 is a real answer, so it
  doesn't trigger the fallback.
- **Shared replay protection:** both gateways keep last-seen counters in one
  SQLite file on the `gateway-state` volume, updated with a single atomic
  statement. Without this, a chunk accepted by `gateway-1` could be replayed
  to `gateway-2`, which would never have seen it. As a side effect, counters
  now also survive gateway restarts.

Each response and log line names the instance that handled it
(`"gateway": "gateway-1"`), so round-robin and failover are visible in a demo:

```bash
docker compose stop gateway-1     # crash one instance: every chunk goes to gateway-2
docker compose stop gateway-lb    # the board falls back to :8011
docker compose start gateway-1 gateway-lb
```

### What it solves, and what it doesn't

**Solves: a gateway being unavailable.** A crashed, restarting or overloaded
instance no longer means lost readings. The load balancer routes around it,
and the firmware routes around the load balancer.

**Doesn't need to solve: a gateway being compromised.** More instances don't
make any one of them more trustworthy, but they don't need to be: gateways hold
only device *public* keys, so a compromised instance can't forge a device's
ECDSA signature, and the fork's end-to-end check catches any data it alters
(`gateway-tampered-after-verification`), however many gateways exist.
Redundancy is for availability; the signature chain is for integrity.

**Also not solved:**

- **The host is a single point of failure.** Both instances, the load
  balancer and the counter file are on one machine (and one Docker volume). If
  the whole host goes down, so does everything; only a fallback gateway on a
  second machine would help, and that machine would need its own way to share
  counters (e.g. a small database both can reach).
- **Downstream is still single-instance.** One fork, edge, cloud and
  validation; if the fork is down, both gateways return 502.
- **A timed-out chunk may be resent.** If the primary accepted a chunk but its
  reply was lost, the fallback gets the same chunk and rejects it as a replay
  (409). That's correct, and the data isn't duplicated, but the board reports
  it as rejected even though it went through.
