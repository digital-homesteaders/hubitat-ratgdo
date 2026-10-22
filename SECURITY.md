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

## Where the key is stored on the hub

The key is a password-type setting, which hides it on screen. It is **not
encrypted by the driver**, and anyone signed in to the hub's web page can reveal
it. Encrypting it inside the driver would add nothing: the driver needs the
plain key for every connection, so whatever unlocked it would sit on the same
hub. What actually protects it:

- **Hub Login Security** (Settings > Hub Login Security). Without it, anyone on
  your network can open the hub, reveal the key and open the garage.
- **Hub backups**, local and cloud, contain the settings. Keep them private.
- **A separate key per ratgdo**, so one leak affects one door.
- **Firewall the API port.** If only the hub and Home Assistant can reach TCP
  6053 on the ratgdo, a leaked key is useless anywhere else on your network.
- **Changing the key** if you think it leaked: put a new key in the YAML, flash
  it, then update Hubitat and Home Assistant.

## Known limits

- The X25519 code isn't constant-time. Its secret is a fresh ephemeral key per
  connection, and the attacker would have to time the hub's handshakes from
  your LAN, so we consider the risk negligible.
- ESPHome's Noise handshake proves the ratgdo knows the key. Anyone else who
  knows it, such as Home Assistant, can also connect. Keep the key private.
