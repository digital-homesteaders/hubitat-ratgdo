# Security

This driver's job is to keep the connection to your garage door encrypted, so
we take reports seriously.

**Please report vulnerabilities privately**, through GitHub's
[private vulnerability reporting](https://github.com/digital-homesteaders/hubitat-ratgdo/security/advisories/new),
not in a public issue. Include the driver version and the steps to reproduce.
We aim to reply within a week.

## What the driver does with secrets

- The API key is a password-type preference. It is never logged, never put in
  device state or events, and never sent over the network: the Noise handshake
  proves both sides hold it without revealing it.
- Session keys, nonces and the ephemeral private key live only in memory, for
  the life of one connection.
- A ratgdo that answers without encryption is refused, never downgraded.

## Known limits

- The X25519 code isn't constant-time. Its secret is a fresh ephemeral key per
  connection, and the attacker would have to time the hub's handshakes from
  your LAN, so we consider the risk negligible.
- ESPHome's Noise handshake proves the ratgdo knows the key. Anyone else who
  knows it, such as Home Assistant, can also connect. Keep the key private.
