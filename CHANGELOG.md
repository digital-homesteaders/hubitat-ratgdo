# Changelog

## Unreleased

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
