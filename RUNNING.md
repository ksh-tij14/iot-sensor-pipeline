# Running the project yourself

A step-by-step guide for running and demonstrating the project on your own
PC. For what the project *is*, see the [README](README.md).

## What you need (one-time setup, already done on this PC)

- **Docker Desktop**: runs the services and the dashboard.
- **VS Code + PlatformIO extension**: builds and uploads the firmware.
- **Python 3** with `pip install -r requirements.txt`: for the scripts and tests.
- **The NodeMCU ESP8266 + DHT11**, wired:

  | DHT11 pin | NodeMCU pin |
  |---|---|
  | `+` | **3V3** |
  | `out` | **D2** |
  | `-` | **GND** |

- **The `vivo V27` hotspot (2.4 GHz)**: both the PC and the board must join it.
- Windows set to treat the hotspot as a **Private** network (Settings → Network & internet → Wi-Fi → vivo V27 → Private).

## Once, before a real demo: real keys

The committed keys and certificates are **public dev material** for tests.
Replace them with real ones. Plug the board in by USB, then from
`C:\iot-sensor-pipeline`:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\rotate-keys.ps1
```

It checks the board is connected, then:

1. generates a new ECDSA key pair for every sensor, a TLS certificate, and
   new gateway and event-log keys (into gitignored files);
2. writes the board's private key **only** into the firmware's `secrets.h`;
3. flashes the board twice (once to store its new key, once to return to
   normal firmware);
4. restarts the Docker stack on the new keys.

Re-run it whenever you want fresh keys.

## Every time you run it

### 1. Connect the PC to the hotspot

Turn on the phone hotspot and connect the PC to `vivo V27`.

### 2. Start everything with one command

From `C:\iot-sensor-pipeline`:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\start-demo.ps1
```

The script:

1. starts Docker Desktop if it isn't running;
2. starts all eight services and waits until they're healthy;
3. checks the firmware points at your PC's **current** IP address;
4. opens the **dashboard** at http://localhost:8080.

If step 3 says **MISMATCH** (the hotspot gave the PC a new address), plug the
board in by USB and run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\start-demo.ps1 -FixFirmware
```

### 3. Power the board

Plug it into USB or a power bank. Within about 20 seconds it joins the hotspot
and starts sending a signed reading every 5 seconds over HTTPS.

### 4. Watch the readings arrive

On the dashboard, **Main Overview** shows the board as online, the latest
validated reading and a live chart. **Event Ledger** lists every event; press
**Verify Integrity** to check that the log hasn't been tampered with.

To see the board's own output (board plugged into the PC), from
`C:\iot-sensor-pipeline\firmware`:

```powershell
& "$env:USERPROFILE\.platformio\penv\Scripts\pio.exe" device monitor
```

Expect lines like `counter=42 temp=30.2C hum=59.0% sign=…ms via primary -> HTTP 200 OK`.

### 5. Run the attack demo

On the dashboard, open **Threat Simulator** and press any attack's button, or
**Run All Attacks**. Or from PowerShell, in `C:\iot-sensor-pipeline\docker`:

```powershell
docker compose run --rm attack-simulator
```

All eight attacks should show `PASS`. The real board keeps sending undisturbed.

### 6. Run the benchmark

On the dashboard: **System Health → Run Benchmark** (about 5 seconds). For the
full run used in the paper, in `C:\iot-sensor-pipeline\docker`:

```powershell
docker compose run --rm attack-simulator python -m tests.benchmark --genuine 100 --runs 10
```

### 7. Show revocation (optional)

From `C:\iot-sensor-pipeline`:

```powershell
python scripts\revoke_sensor.py esp32-001             # the board's readings are refused immediately
python scripts\revoke_sensor.py esp32-001 --restore   # accepted again
```

### 8. Show packet dropping (live)

Unplug the board (or turn off the hotspot) for about 20 seconds, then
reconnect. The readings stop, nothing crashes, and they resume within about
10 seconds.

### 9. Show gateway failover (optional)

```powershell
docker compose stop gateway-1     # readings carry on through gateway-2
docker compose stop gateway-lb    # the board switches to its fallback address (:8011)
docker compose start gateway-1 gateway-lb
```

### 10. Stop everything

```powershell
cd docker
docker compose down
```

Stored data (backups, results, counters, event log) is kept. To wipe it, use
`docker compose down -v`.

## No board? Use the virtual sensor board

`tests/virtual_board.py` is a software stand-in for the ESP8266. It has its own
identity (`esp32-002`) and ECDSA key, and every 5 seconds signs a simulated
reading and sends it over HTTPS through the gateway, so it passes every check a
real reading does. The dashboard's device menu (top bar) shows both boards;
**Auto** shows the physical board when it's live, otherwise the virtual one.

```powershell
powershell -ExecutionPolicy Bypass -File scripts\start-demo.ps1 -Virtual
```

Or from `docker/`: `docker compose --profile demo up -d virtual-board`, and
`docker compose --profile demo stop virtual-board` to stop it. In VS Code: tasks
**1b** and **1c**. It never uses the physical board's identity, so the dashboard
always shows which device a reading came from.

## Long-run (soak) test, for the paper

1. Start everything (task **1**), power the board, and leave it running for an
   hour or more. Don't run attacks during the run.
2. Then, from `docker\`:

   ```powershell
   docker compose exec dashboard python -m tests.soak_report --hours 1
   ```

   It reports readings delivered vs expected, gaps over 10 s, counter values
   skipped by failed sends, and how many were validated end to end.
3. For the send time per reading (TLS handshake + the pipeline's response),
   watch the board with task **3**: each line shows `sign=…ms send=…ms`.

## Running the unit tests

In `C:\iot-sensor-pipeline`:

```powershell
python -m pytest -q
```

## If something goes wrong

| What you see | What to do |
|---|---|
| Board prints `send failed` with a connection or TLS error | The PC's IP changed, or the firewall blocks port 8443: run `start-demo.ps1 -FixFirmware`, and check the hotspot is **Private** |
| Board prints `HTTP 401` | The board's key doesn't match the stack's: run `rotate-keys.ps1` (board on USB) |
| Board prints `HTTP 409` every time | Either the clock is off (`stale_timestamp`: check the board says "Time synced"), or the gateways have seen a higher counter (e.g. you erased the board's flash): run `docker compose down -v` to reset stored counters |
| Board prints `HTTP 403` | The board is revoked: `python scripts\revoke_sensor.py esp32-001 --restore` |
| Board prints `No valid private key` | Run `rotate-keys.ps1` |
| Board prints `WiFi not connected` | Hotspot off, on 5 GHz, or the password changed (`firmware/include/secrets.h`) |
| Board prints `DHT11 read failed` | Check the data wire is on **D2** and pushed in firmly |
| Dashboard shows the board **offline** | It hasn't been accepted for 15 s: check its power, the hotspot and the output above |
| `rotate-keys.ps1` says no board found | Plug the board into this PC by USB (not a power bank) |
| PowerShell refuses to run a script | Use the full `powershell -ExecutionPolicy Bypass -File ...` form |
| `pio` isn't recognised | Use the full path: `& "$env:USERPROFILE\.platformio\penv\Scripts\pio.exe"` |
