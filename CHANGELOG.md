# Changelog

## Unreleased

- **Restart**: reboots the ratgdo with its own Restart button; the driver reconnects by itself.
- A door stopped part-way logs its position: "door is open (25%)".
- **Preset Position**: a 0, 25, 50, 75 or 100% dropdown next to Set Position, like Home Assistant's door buttons.
- `lastError` reads "none" once connected, instead of an empty value that the device page shows as "null".
- The opener's wall button is a PushableButton (`pushed` 1 on each press), for rules.
- `healthStatus`, Hubitat's standard online/offline attribute.
- A different ESPHome device at the ratgdo's address is reported by name, instead of as a wrong key; a wrong key names the device too.
- Save and uninstall say goodbye to the ratgdo (ESPHome's DisconnectRequest), freeing its connection slot at once.
- Two updates in one burst no longer log the same change twice (seen on a C-8).
- While the door moves, `position` is reported every 10% instead of about twice a second; the final position is exact.
- Toggle on firmware without a Toggle button (SecplusGDO) stops a moving door instead of reversing it.
- Gelidus Research GRGDO boards (ESPHome RATGDO or SecplusGDO firmware); their ultrasound "Vehicle parked" sets `presence`.
- ratgdo32 Disco: `presence` (vehicle detected) and `vehicleMotion` (arriving, leaving). With the encoder: `manuallyOperated`.
- The API port setting is text, so the settings page shows 6053 instead of "6,053".

## 0.1.0 (2026-10-22)

First release.

- Local, encrypted control of a ratgdo running ESPHome, through the native API
  with the ratgdo's API key (Noise_NNpsk0_25519_ChaChaPoly_SHA256), as Home
  Assistant does.
- Door (open, close, stop, toggle, set position), contact, position, light
  (with an optional component device), motion, obstruction, motor, remote lock
  and openings.
- `networkStatus` and `lastError`; reconnects back off up to 5 minutes, and a
  wrong key retries every 30 minutes.
