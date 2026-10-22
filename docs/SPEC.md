# ratgdo (ESPHome) for Hubitat: design

One Hubitat driver that talks to a ratgdo running ESPHome firmware the same way
Home Assistant does: over the ESPHome **native API**, encrypted with the
device's **API key**. No broker, no cloud, no web server, no extra hub app.

## Goals

- **Encrypted only.** The API key is required. A device that answers in
  plaintext is refused, and so is a wrong key.
- **Lean.** One driver file, no app, no library. The light uses Hubitat's
  built-in Generic Component Switch. Crypto runs only on connect; after that
  each update is one small decrypt.
- **Push, not polling.** The ratgdo sends every change over one open
  connection, as it does for Home Assistant.
- **Runs on a C-7 as well as a C-8.** The crypto is plain Groovy (no Java 11
  crypto classes), and reconnects back off.
- **Side by side with Home Assistant.** Hubitat is just one more API client.
  An ESP8266 ratgdo allows 4 clients, about 0.5–1 KB of RAM each.

Out of scope: plaintext devices, the API password (removed in ESPHome
2026.1), the ratgdo's MQTT and HomeKit firmware, Bluetooth proxies, discovery
(enter the IP; Hubitat can't resolve `.local` names), and settings such as
opening duration or the learn switch, which belong in the ESPHome dashboard.

## Transport

| Step | Client (Hubitat) | ratgdo |
|---|---|---|
| 1 | TCP to port 6053 (`interfaces.rawSocket`, `byteInterface: true`) | |
| 2 | `01 00 00` (hello), then `01 LL LL 00` + Noise message 1 | |
| 3 | | `01 LL LL 01 name\0 mac\0`: server hello |
| 4 | | `01 LL LL 00` + Noise message 2, or `01 LL LL 01 reason`: rejected |
| 5 | encrypted `HelloRequest` + empty `AuthenticationRequest` | `HelloResponse` |
| 6 | `DeviceInfoRequest`, `ListEntitiesRequest` | device info, one message per entity, `ListEntitiesDoneResponse` |
| 7 | `SubscribeStatesRequest` | every current state, then each change |

Every frame is `0x01`, a 16-bit big-endian length, then the payload. After the
handshake the payload is ChaCha20-Poly1305 ciphertext of
`type(u16 BE) len(u16 BE) protobuf`. The empty login message is for firmware
before 2026.1. Newer firmware ignores message types it doesn't know.

### Noise

`Noise_NNpsk0_25519_ChaChaPoly_SHA256`, prologue `"NoiseAPIInit\0\0"`. The
PSK is the API key's 32 bytes, from base64.

- `h = ck = SHA256(protocol name)`, then `MixHash(prologue)`.
- Message 1 (`psk, e`): `MixKeyAndHash(psk)`; `MixHash(e.pub)`; `MixKey(e.pub)`;
  `EncryptAndHash("")`, which gives `e.pub` (32) and a tag (16).
- Message 2 (`e, ee`): `MixHash(re)`; `MixKey(re)`; `MixKey(DH(e, re))`;
  `DecryptAndHash` of the 16-byte tag. A failed tag means a wrong key.
- `Split()`: the first key sends, the second receives. Nonces count from 0 as
  `00000000 || u64 LE`. The associated data is empty.

The crypto is hand-written: X25519 (RFC 7748) on `BigInteger`, ChaCha20 and
Poly1305 (RFC 8439). Only SHA-256 and HMAC come from the JDK
(`MessageDigest`, `Mac`), which every Hubitat model has. The ephemeral key is
32 bytes from `SecureRandom`, new for each connection. The ladder is not
constant-time, which is acceptable for a one-off ephemeral key on a LAN.

Keys, nonces and the receive buffer live in a `@Field static
ConcurrentHashMap` keyed by device id. They are never written to `state`, so
they never reach the database or the device page, and they vanish on reboot
along with the socket. The driver is `singleThreaded: true`, so parse,
commands and timers never interleave and nonces stay in order.

## Messages used

| ID | Message | Fields read or written |
|---|---|---|
| 1 / 2 | Hello request / response | client_info=1, api_version 1.10 |
| 3 / 4 | Authentication | empty; `invalid_password`=1 is reported |
| 5 / 6 | Disconnect request / response | |
| 7 / 8 | Ping request / response | |
| 9 / 10 | Device info | name=2, esphome_version=4, model=6, project_name=8, project_version=9, friendly_name=13 |
| 11, 19, 20 | List entities, done, subscribe states | |
| 12 / 21 | Binary sensor | key=2, object_id=1, name=3 / key=1, state=2, missing_state=3 |
| 13 / 22 / 30 | Cover | key / position=3 (float), current_operation=5 / key=1, has_position=4, position=5, stop=8 |
| 15 / 24 / 32 | Light | key / state=2 / key=1, has_state=2, state=3 |
| 16 / 25 | Sensor | key / state=2 (float), missing_state=3 |
| 58 / 59 / 60 | Lock | key / state=2 / key=1, command=2 |
| 61 / 62 | Button | key / key=1 |
| 36 / 37 | Get time | epoch_seconds=1 (fixed32) |

Unknown types are skipped.

## Entities to Hubitat

An entity is matched by domain plus a word in its `object_id` or name, so a
renamed `id_prefix`, a v2.5/v32 board, or Gelidus's SecplusGDO firmware ("Garage
Door", "Garage Motion Sensor", "Garage Door Openings") still lines up.

| ratgdo entity | Hubitat |
|---|---|
| cover (first, `garage` preferred) | `door` (open, closed, opening, closing), `contact`, `position` 0–100; `open`, `close`, `stop`, `setPosition`, `toggle` |
| light | `light` attribute; `lightOn`/`lightOff`; the optional child Generic Component Switch |
| lock "Lock remotes" | `remotes` (locked, unlocked); `lockRemotes`/`unlockRemotes` |
| binary_sensor motion / obstruction / motor | `motion` (active, inactive), `obstruction` (obstructed, clear), `motor` (running, idle) |
| sensor openings | `openings` |
| binary_sensor vehicle detected (Disco) or vehicle parked (Gelidus ultrasound) | `presence` (present, not present) |
| binary_sensor vehicle arriving / leaving (Disco, Gelidus ultrasound) | `vehicleMotion` (arriving, leaving, none) |
| binary_sensor manually operated (encoder) | `manuallyOperated` (yes, no) |
| button "Toggle door" | used by `toggle` when present |
| button "Query status" | used by `refresh` when present |

Door state: `current_operation` 1 means opening and 2 means closing.
Otherwise position 0 is `closed` and any other position is `open`. The contact
is `closed` only when the door is closed. Protobuf leaves out zero values, so a
missing position is 0, which is closed.

Left out on purpose: the encoder step count, the Disco's vehicle distance
(every few seconds; too chatty for hub events), laser, LED, voltage and Wi-Fi
signal, and every config number. With the encoder, the cover's own position is
encoder-based, so nothing extra is needed for an exact `position`.

`toggle` presses the ratgdo's own Toggle button, so it can stop a moving door.
Without that button (SecplusGDO) it stops a moving door, opens a closed one
and closes any other.

## Health

- `networkStatus` is connecting, online (after the entity list), offline or
  bad key. `lastError` says why in plain words.
- The watchdog runs every minute. It pings after 50 s with nothing received and
  reconnects after 150 s. The ratgdo pings on its own after 60 s quiet and
  drops a client after 150 s.
- Reconnects wait 5, 10, 20 s and so on, up to 5 minutes. A wrong key, or a
  device without encryption, retries every 30 minutes and says so once.
- The handshake has 15 s to finish.
- `initialize()` runs on hub start (capability Initialize) and on Save.
- Saving new driver code clears the in-memory session but may leave the socket
  open. The watchdog sees `online` with no session and reconnects.
- Socket errors count only once the session is ready. A late error from an
  old socket can't knock down a new handshake, which has its own timeout.
- **Refresh** while offline connects straight away.

## Tests

`tests/run.sh`, no hub needed:

- **CryptoTest**: RFC 7748 X25519 vectors, RFC 8439 ChaCha20 block, Poly1305
  and AEAD vectors, and a full NNpsk0 transcript plus four transport frames
  from the Python `noise` library aioesphomeapi uses
  (`tests/fixtures/noise-vectors.json`), byte for byte.
- **DriverFlowTest**: the driver against a fake ratgdo that does the responder
  side of the handshake. It covers frames split and joined in any way, entity
  mapping, every state and every command's bytes, ping, get time, disconnect,
  wrong key, a plaintext device, timeouts, backoff and the light child.
- **CompileCheck** and **PackageCheck**: Groovy 2.4 compile, ASCII only, no
  post-2.4 methods, and the manifest, version and import URL agree.
