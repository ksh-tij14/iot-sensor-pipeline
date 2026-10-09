// Sensor node (ESP8266 NodeMCU or ESP32): reads a DHT11, signs each reading
// with its own ECDSA P-256 private key and POSTs it over HTTPS (with the
// gateway's key pinned) as a SignedChunk (see shared/schemas.py).
// Board differences are confined to the #if blocks.

#include <Arduino.h>
#include <DHT.h>
#include <Preferences.h>  // ESP32 built-in; on ESP8266 a port that stores to flash (LittleFS)
#include <inttypes.h>
#include <sys/time.h>
#include "secrets.h"  // WiFi, SENSOR_PRIVATE_KEY, gateway TLS key/cert (gitignored)

#if defined(ESP8266)
  #include <ESP8266WiFi.h>
  #include <ESP8266HTTPClient.h>
  #include <WiFiClientSecureBearSSL.h>
  #include <bearssl/bearssl.h>  // ECDSA + SHA-256 (BearSSL ships with the ESP8266 core)
  #define BOARD_NAME "ESP8266"
#else
  #include <WiFi.h>
  #include <HTTPClient.h>
  #include <WiFiClientSecure.h>
  #include <esp_system.h>
  #include "mbedtls/ecdsa.h"
  #include "mbedtls/md.h"
  #define BOARD_NAME "ESP32"
#endif

// ---- Per-device settings: change these when flashing another board ----
// SENSOR_ID must match an entry in the gateway's keystore, holding the public
// key that matches SENSOR_PRIVATE_KEY in secrets.h (scripts/generate_secrets.py
// writes both). Use only letters, digits, '-' and '_' (the ID goes into JSON unescaped).
#define SENSOR_ID "esp32-001"
#define GATEWAY_URL "https://10.114.82.135:8443/ingest"
// Tried only if GATEWAY_URL doesn't answer at all. Here: gateway-2 directly,
// bypassing the Docker load balancer; ideally a gateway on a second machine.
// Set to "" to disable.
#define GATEWAY_URL_FALLBACK "https://10.114.82.135:8011/ingest"
#define CHUNK_INTERVAL_SECONDS 2  // mirrors CHUNK_INTERVAL_SECONDS in shared/config.py

// If the primary gateway can't be connected to within this time, try the
// fallback. Short, so a dead primary costs little; if both attempts outlast
// the 2 s interval, the next reading simply starts late (none is skipped).
#define GATEWAY_CONNECT_TIMEOUT_MS 1500
#define GATEWAY_RESPONSE_TIMEOUT_MS 5000

// Set to 1 for one flash to overwrite the sensor_id/private key already stored
// in flash (new keys, or reusing a board as a different sensor), then back to 0.
#define FORCE_REPROVISION 0

// GPIO4 on both boards, but printed differently: "D2" on a NodeMCU ESP8266
// (whose "D4" is GPIO2, a boot pin to avoid), "D4" on an ESP32 DevKit.
#define DHT_PIN 4
#define DHT_TYPE DHT11
#define NVS_NAMESPACE "sensor_cfg"
#define WIFI_RETRY_MS 10000
#define MIN_VALID_EPOCH 1700000000  // anything earlier means NTP hasn't synced yet

DHT dht(DHT_PIN, DHT_TYPE);
Preferences prefs;

String sensorId;
uint8_t privateKey[32];   // ECDSA P-256 private key, loaded from flash
uint32_t counter = 0;
bool identityOk = false;
unsigned long lastChunkMs = 0;
unsigned long lastWifiAttemptMs = 0;

bool hexToBytes(const char* hex, uint8_t* out, size_t len) {
  if (strlen(hex) != len * 2) return false;
  for (size_t i = 0; i < len; i++) {
    char byteStr[3] = {hex[2 * i], hex[2 * i + 1], 0};
    char* end;
    out[i] = (uint8_t)strtoul(byteStr, &end, 16);
    if (*end) return false;
  }
  return true;
}

// First boot: copy identity from secrets.h into flash. Every boot after that:
// read it from flash only, as if it had been provisioned at the factory.
bool loadOrProvisionIdentity() {
  if (FORCE_REPROVISION || !prefs.isKey("sensor_id") || !prefs.isKey("privkey")) {
    Serial.println("Provisioning: writing sensor_id and private key to flash");
    prefs.putString("sensor_id", SENSOR_ID);
    prefs.putString("privkey", SENSOR_PRIVATE_KEY);
    prefs.remove("secret");                     // the old shared HMAC key, if any
  }
  sensorId = prefs.getString("sensor_id");
  counter = prefs.getUInt("counter", 0);
  bool ok = hexToBytes(prefs.getString("privkey").c_str(), privateKey, sizeof(privateKey));
  Serial.printf("Sensor %s, counter %" PRIu32 "%s\n", sensorId.c_str(), counter,
                ok ? "" : "  -- INVALID PRIVATE KEY, not sending");
  return ok;
}

// Non-blocking reconnect: at most one attempt every WIFI_RETRY_MS.
bool ensureWifi() {
  if (WiFi.status() == WL_CONNECTED) return true;
  if (millis() - lastWifiAttemptMs >= WIFI_RETRY_MS) {
    lastWifiAttemptMs = millis();
    Serial.println("WiFi down, reconnecting...");
    WiFi.disconnect();
    WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
  }
  return false;
}

bool timeIsSynced() {
  return time(nullptr) > MIN_VALID_EPOCH;
}

uint64_t nowMillis() {
  struct timeval tv;
  gettimeofday(&tv, nullptr);
  return (uint64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

// Decimal string of a uint64_t. Avoids %llu, which not every printf build supports.
void u64ToStr(uint64_t v, char out[21]) {
  char tmp[21];
  int n = 0;
  do { tmp[n++] = '0' + (v % 10); v /= 10; } while (v);
  for (int i = 0; i < n; i++) out[i] = tmp[n - 1 - i];
  out[n] = '\0';
}

#if defined(ESP8266)
// ECDSA needs a few KB of stack, more than the 4 KB loop() stack has. Run it on
// BearSSL's separate stack, the way the core's own TLS code does.
#include <StackThunk.h>
extern "C" size_t thunk_br_ecdsa_i15_sign_raw(const br_ec_impl*, const br_hash_class*, const void*,
                                              const br_ec_private_key*, void*);
make_stack_thunk(br_ecdsa_i15_sign_raw);
#endif

#if !defined(ESP8266)
static int espRandom(void*, unsigned char* out, size_t len) {
  esp_fill_random(out, len);
  return 0;
}
#endif

// ECDSA P-256 over SHA-256(msg), as raw r||s in lowercase hex (128 chars),
// the format shared/crypto_utils.ecdsa_verify expects.
bool ecdsaSignHex(const char* msg, char out[129]) {
  uint8_t hash[32], sig[64];
#if defined(ESP8266)
  br_sha256_context sc;
  br_sha256_init(&sc);
  br_sha256_update(&sc, msg, strlen(msg));
  br_sha256_out(&sc, hash);
  br_ec_private_key sk = {BR_EC_secp256r1, privateKey, sizeof(privateKey)};
  // Deterministic nonces (RFC 6979), so no random number generator is needed.
  stack_thunk_add_ref();
  size_t sigLen = thunk_br_ecdsa_i15_sign_raw(br_ec_get_default(), &br_sha256_vtable, hash, &sk, sig);
  stack_thunk_del_ref();
  if (sigLen != 64) return false;
#else
  const mbedtls_md_info_t* info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  if (mbedtls_md(info, (const uint8_t*)msg, strlen(msg), hash) != 0) return false;
  mbedtls_ecp_group grp;
  mbedtls_mpi d, r, s;
  mbedtls_ecp_group_init(&grp);
  mbedtls_mpi_init(&d); mbedtls_mpi_init(&r); mbedtls_mpi_init(&s);
  int rc = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
  if (rc == 0) rc = mbedtls_mpi_read_binary(&d, privateKey, sizeof(privateKey));
  if (rc == 0) rc = mbedtls_ecdsa_sign(&grp, &r, &s, &d, hash, sizeof(hash), espRandom, nullptr);
  if (rc == 0) rc = mbedtls_mpi_write_binary(&r, sig, 32);
  if (rc == 0) rc = mbedtls_mpi_write_binary(&s, sig + 32, 32);
  mbedtls_ecp_group_free(&grp);
  mbedtls_mpi_free(&d); mbedtls_mpi_free(&r); mbedtls_mpi_free(&s);
  if (rc != 0) return false;
#endif
  for (int i = 0; i < 64; i++) sprintf(out + i * 2, "%02x", sig[i]);
  return true;
}

const char* wifiStatusText(wl_status_t s) {
  switch (s) {
    case WL_NO_SSID_AVAIL: return "network not found - check the name, and that it's 2.4 GHz";
    case WL_CONNECT_FAILED: return "connection failed - check the password / WPA2 security";
    case WL_CONNECTION_LOST: return "connection lost";
    case WL_DISCONNECTED: return "disconnected - often a wrong password";
    case WL_IDLE_STATUS: return "idle";
    default: return "unknown";
  }
}

// Debug aid: list the 2.4 GHz networks the board can see.
void printVisibleNetworks() {
  int n = WiFi.scanNetworks();
  Serial.printf("Networks visible to the board (%d):\n", n);
  for (int i = 0; i < n; i++) {
    Serial.printf("  \"%s\"  signal %d dBm\n", WiFi.SSID(i).c_str(), WiFi.RSSI(i));
  }
  Serial.printf("Looking for: \"%s\"\n", WIFI_SSID);
  WiFi.scanDelete();
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);  // the scan interrupts the connection attempt
}

// POST one chunk. Returns the HTTP status, or a negative HTTPClient error code
// if there was no response (connection refused, unreachable, timeout).
// TLS: the connection is encrypted, and the board only talks to the real
// gateway - the ESP8266 pins the gateway's certificate fingerprint, the ESP32
// checks its certificate. Anyone else answering on that address is refused.
int postChunk(const char* url, const char* body) {
  HTTPClient http;
#if defined(ESP8266)
  BearSSL::WiFiClientSecure client;
  // Not setKnownKey(): the core's public-key pinning rejects valid ECDSA
  // ServerKeyExchange signatures (TLS error 27). Pinning the certificate works.
  client.setFingerprint(GATEWAY_TLS_FINGERPRINT);
  // Resume the previous TLS session with this gateway: skips the ECDHE + ECDSA
  // handshake maths (~1 s at 160 MHz). The session was authenticated, with the
  // fingerprint check, by the full handshake that created it.
  static BearSSL::Session primarySession, fallbackSession;
  client.setSession(strcmp(url, GATEWAY_URL) == 0 ? &primarySession : &fallbackSession);
  // The ESP8266 client has a single timeout covering connect and response.
  http.setTimeout(GATEWAY_RESPONSE_TIMEOUT_MS);
  http.begin(client, url);
#else
  WiFiClientSecure client;
  client.setCACert(GATEWAY_TLS_CERT);
  http.setConnectTimeout(GATEWAY_CONNECT_TIMEOUT_MS);
  http.setTimeout(GATEWAY_RESPONSE_TIMEOUT_MS);
  http.begin(client, url);
#endif
  http.addHeader("Content-Type", "application/json");
  int status = http.POST((uint8_t*)body, strlen(body));
#if defined(ESP8266)
  if (status < 0) {
    char err[80];
    if (client.getLastSSLError(err, sizeof(err)) != 0) Serial.printf("  TLS: %s\n", err);
  }
#endif
  http.end();
#if defined(ESP8266)
  // The core saves the TLS session for resumption only in stop(); http.end()
  // skips it when the server has already closed the connection.
  client.stop();
#endif
  return status;
}

void setup() {
  Serial.begin(115200);
  delay(500);
  Serial.println("\nSensor node starting (" BOARD_NAME ")");

  dht.begin();
  prefs.begin(NVS_NAMESPACE, false);
  identityOk = loadOrProvisionIdentity();

  // Lower transmit power = smaller current spike. Avoids brownout resets on
  // weak USB supplies; plenty of range for a hotspot a few metres away.
  WiFi.mode(WIFI_STA);
#if defined(ESP8266)
  WiFi.setOutputPower(8.5);  // dBm
#else
  WiFi.setTxPower(WIFI_POWER_8_5dBm);
#endif
  WiFi.setAutoReconnect(true);
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
#if !defined(ESP8266)
  WiFi.setTxPower(WIFI_POWER_8_5dBm);
#endif
  lastWifiAttemptMs = millis();

  // Wait up to 20 s for the first connection, but don't block forever:
  // loop() keeps retrying if this fails.
  while (WiFi.status() != WL_CONNECTED && millis() - lastWifiAttemptMs < 20000) {
    delay(500);
    Serial.print(".");
  }
  Serial.println();
  if (WiFi.status() == WL_CONNECTED) {
    Serial.print("WiFi connected, IP: ");
    Serial.println(WiFi.localIP());
  } else {
    Serial.printf("WiFi not connected yet (%s), will keep retrying\n", wifiStatusText(WiFi.status()));
    printVisibleNetworks();
  }

  // UTC. SNTP keeps syncing in the background, including after a late WiFi connect.
  configTime(0, 0, "pool.ntp.org", "time.nist.gov");
  unsigned long ntpStart = millis();
  while (!timeIsSynced() && WiFi.status() == WL_CONNECTED && millis() - ntpStart < 10000) {
    delay(250);
  }
  Serial.println(timeIsSynced() ? "Time synced via NTP" : "Time not synced yet, will retry");
}

void loop() {
  bool wifiUp = ensureWifi();

  if (millis() - lastChunkMs < CHUNK_INTERVAL_SECONDS * 1000UL) return;
  lastChunkMs = millis();

  // a. Read the sensor; on a failed read skip this interval entirely.
  float humidity = dht.readHumidity();
  float tempC = dht.readTemperature();
  // Some DHT11 variants set the top bit of the temperature's decimal byte,
  // which the Adafruit library reads as a minus sign: it returns
  // -1 - whole + decimal/10 (25.0 C reads as -26.0, 30.2 C as -30.8).
  // A DHT11 can't measure below 0 C, so invert that exactly:
  // whole + decimal/10 = t - 2*floor(t) - 1.
  if (DHT_TYPE == DHT11 && tempC < 0) tempC = tempC - 2.0f * floorf(tempC) - 1.0f;
  if (isnan(humidity) || isnan(tempC)) {
    Serial.println("DHT11 read failed, skipping this interval");
    return;
  }

  if (!wifiUp) {
    Serial.println("No WiFi, skipping this interval");
    return;
  }
  if (!timeIsSynced()) {
    Serial.println("Time not synced, skipping this interval");
    return;
  }
  if (!identityOk) {
    Serial.println("No valid private key in flash (re-flash with FORCE_REPROVISION 1), not sending");
    return;
  }

  // b. Bump and persist the counter BEFORE sending, so a failed or
  //    interrupted send can never lead to the same counter being reused.
  uint32_t next = counter + 1;
  if (prefs.putUInt("counter", next) == 0) {
    Serial.println("Failed to write counter to NVS, not sending");
    return;
  }
  counter = next;

  // c. Integers only (hundredths), so the JSON is byte-identical to Python's.
  long tempCenti = lroundf(tempC * 100.0f);
  long humidityCenti = lroundf(humidity * 100.0f);
  char timestamp[21];
  u64ToStr(nowMillis(), timestamp);

  // d. Canonical signing string: must match SignedChunk.signing_bytes() in
  //    shared/schemas.py exactly - compact JSON, keys sorted alphabetically.
  char signingStr[256];
  snprintf(signingStr, sizeof(signingStr),
           "{\"counter\":%" PRIu32
           ",\"data\":{\"humidity_centi_pct\":%ld,\"temp_centi_c\":%ld}"
           ",\"sensor_id\":\"%s\",\"timestamp\":%s}",
           counter, humidityCenti, tempCenti, sensorId.c_str(), timestamp);

  char signature[129];
  unsigned long signStart = millis();
  bool signedOk = ecdsaSignHex(signingStr, signature);
  unsigned long signMs = millis() - signStart;
  if (!signedOk) {
    Serial.println("HMAC failed, not sending");
    return;
  }

  // e. Full envelope, matching SignedChunk's fields (gateway_signature is added later).
  char body[448];
  snprintf(body, sizeof(body),
           "{\"sensor_id\":\"%s\",\"timestamp\":%s,\"counter\":%" PRIu32
           ",\"data\":{\"humidity_centi_pct\":%ld,\"temp_centi_c\":%ld}"
           ",\"sensor_signature\":\"%s\"}",
           sensorId.c_str(), timestamp, counter, humidityCenti, tempCenti, signature);

  // Try the primary gateway; fall back only if it gave no HTTP response at all
  // (refused, unreachable, timed out). An HTTP error such as 401 or 409 is a
  // real answer - resending the same chunk elsewhere wouldn't change it.
  bool usedFallback = false;
  // Send time = TLS handshake + HTTPS request + the whole pipeline's response.
  unsigned long sendStart = millis();
  int status = postChunk(GATEWAY_URL, body);
  if (status < 0 && strlen(GATEWAY_URL_FALLBACK) > 0) {
    Serial.printf("primary gateway failed (%s), trying fallback\n",
                  HTTPClient::errorToString(status).c_str());
    usedFallback = true;
    sendStart = millis();
    status = postChunk(GATEWAY_URL_FALLBACK, body);
  }
  unsigned long sendMs = millis() - sendStart;

  // f. Outcome.
  Serial.printf("counter=%" PRIu32 " temp=%.1fC hum=%.1f%% sign=%lums send=%lums via %s -> ",
                counter, tempC, humidity, signMs, sendMs, usedFallback ? "fallback" : "primary");
  if (status > 0) {
    Serial.printf("HTTP %d%s\n", status, status >= 200 && status < 300 ? " OK" : " (rejected)");
  } else {
    Serial.printf("send failed: %s\n", HTTPClient::errorToString(status).c_str());
  }
}
