# Testing

What is checked without a hub, and what still needs a real hub and a real
ratgdo. Hub reports are welcome: use the "It works on my hub" issue form.

## Covered locally (no hub needed)

`tests/run.sh` compiles the driver with Groovy 2.4 (the line Hubitat runs)
against small stand-ins for the hub, then runs:

- **CompileCheck**: the driver compiles and its metadata runs, it is
  `singleThreaded`, no post-2.4 Groovy methods, no sandbox-risky calls
  (`System.`, `.clone()`, `Arrays.` ...), ASCII only, the API key is a
  password input and never appears in a log line.
- **PackageCheck**: the HPM manifest, the driver's name, namespace, import URL
  and version agree; LICENSE points at NOTICE.
- **CryptoTest**: X25519 against RFC 7748 (section 5.2 and the section 6.1
  key exchange), the ChaCha20 block and Poly1305 against RFC 8439, AEAD
  tamper checks, and a whole Noise_NNpsk0 handshake plus four transport frames
  checked **byte for byte** against the Python `noise` library that Home
  Assistant's aioesphomeapi uses (`tests/fixtures/noise-vectors.json`, made by
  `noise_vectors.py`). A wrong key fails the handshake.
- **DriverFlowTest**: the driver against a fake ratgdo that does the device
  side of the handshake and API. It covers frames delivered whole, byte by byte and
  joined; the hello with the empty login, device info (no MAC kept), entity
  mapping for a real ratgdo's entity list; every door, light, lock and sensor
  state, including missing states and unknown keys; the exact bytes of every
  command; Toggle with and without the ratgdo's button; the light child both
  ways; ping and get time; a disconnect request; wrong key (said by the
  device, or only visible as a failed tag); a plaintext device; a malformed
  key; missing settings; backoff 5 s to 300 s; the handshake timeout; the
  watchdog's ping and reconnect; a tampered frame; socket errors (and a late
  one during a new handshake); new driver code clearing memory; refresh while
  offline; and that no key material reaches `state`.

## Confirmed on a real hub

2026-10-22, Hubitat C-8, ratgdo v2.5i (ESP8266, ESPHome firmware, encrypted):

- [x] The sandbox accepts every import (`MessageDigest`, `Mac`, `SecureRandom`,
      `BigInteger`, `ByteArrayOutputStream`) and `interfaces.rawSocket` with
      `byteInterface: true`.
- [x] The encrypted handshake with the real API key, the hello, and the entity
      list: "connected (door, light, motion, motor, obstruction, openings,
      queryButton, remotes, toggleButton)".
- [x] Open, Stop partway and Close from Hubitat; the opener's own light
      reported on and off.
- [x] Live updates when the door is opened and closed from the myQ app.
- [x] Restart: "restarting the ratgdo", then connected again 13 s later.
- [x] Found on the hub: after an apparent fresh start at 03:26, a leftover frame
      ended the next connection ("unknown encryption protocol"); it recovered in
      9 s, and is fixed under Unreleased.
- [x] Set Position and Preset Position: 25, 50, 75, 100 then 0 each stopped
      where asked, about 3.5 s per 25% (log: "door is open (25%)" ...), and the
      position was reported at each stop.
- [x] After Save, the driver reconnects to the same ratgdo (name check) and maps
      the wall button: "connected (... toggleButton, wallButton)".
- [x] Found on the hub: two updates in one burst logged "door is opening" twice
      (fixed; see CHANGELOG, Unreleased).

## Still needs a real hub

- [ ] Handshake time on a C-7 and a C-8 (about 4 ms for both X25519 steps on an M-series Mac; each 40-byte message about 0.04 ms).
- [ ] Stays connected alongside Home Assistant for a day or more.
- [ ] A wall-button press gives `pushed` 1 (physical); `healthStatus` online.
- [ ] Toggle, Light On/Off, Lock/Unlock Remotes.
- [ ] Motion, obstruction and openings update live.
- [ ] Reconnects after a Wi-Fi drop and a hub reboot (a ratgdo reboot is confirmed).
- [ ] ratgdo32, ratgdo32 Disco (vehicle presence, arriving and leaving) and the encoder (`manuallyOperated`, exact position).
- [ ] A Gelidus GRGDO board with SecplusGDO firmware (after adding an API key).
- [ ] Older ESPHome firmware (before 2026.1, which still expects the login message).
