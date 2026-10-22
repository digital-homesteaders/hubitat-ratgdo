# ratgdo (ESPHome) for Hubitat

Your [ratgdo](https://github.com/ratgdo) garage door opener on Hubitat Elevation:
**local, encrypted and instant**. The driver talks to the ratgdo the same way
Home Assistant does, over ESPHome's native API, encrypted with the ratgdo's
**API key**. There's no cloud, no MQTT broker and no polling. A door that
starts moving shows up in Hubitat right away.

It runs alongside Home Assistant. Hubitat is simply a second client, and
nothing on the ratgdo changes.

- **One driver file.** No app is needed. The light can be its own device,
  using Hubitat's built-in Generic Component Switch.
- **Encrypted only.** The API key never leaves the hub. Each connection gets
  fresh session keys, and a ratgdo without encryption is refused.
- **Runs on C-7 and C-8 hubs.** The crypto is plain Groovy and runs only on
  connect. After that, each update is one small decrypt.

> **Status: 0.1.0, not yet confirmed on a real hub.** The protocol is tested
> byte for byte against the library Home Assistant uses, and the driver against
> a simulated ratgdo. See [TESTING.md](TESTING.md). Reports from real hubs are
> very welcome.

## What you get

| In Hubitat | From the ratgdo |
|---|---|
| `door`: open, closed, opening, closing. Commands: **Open**, **Close**, **Stop**, **Toggle**, **Set Position** (0–100), **Preset Position** (0, 25, 50, 75 or 100) | Door |
| `contact`: open or closed (closed only when the door is fully closed) | Door |
| `position`: 0–100 | Door |
| `light` attribute, **Light On** / **Light Off**, plus an optional light device | Light |
| `motion`: active or inactive | Motion |
| `obstruction`: clear or obstructed | Obstruction |
| `motor`: running or idle | Motor |
| `remotes`: locked or unlocked. Commands: **Lock Remotes** / **Unlock Remotes** | Lock remotes |
| `openings` | Openings counter |
| `presence`: present or not present | Vehicle detected (ratgdo32 Disco) or Vehicle parked (Gelidus ultrasound) |
| `vehicleMotion`: arriving, leaving or none | Vehicle arriving and leaving (ratgdo32 Disco, Gelidus ultrasound) |
| `manuallyOperated`: yes or no | Manually Operated (with the ratgdo encoder) |
| `pushed`: button 1, each time the opener's wall button is pressed | Button |
| **Restart**: reboots the ratgdo; the driver reconnects by itself in about 10 s | Restart |
| `networkStatus`: connecting, online, offline or bad key. `lastError` says why. `healthStatus`: Hubitat's standard online or offline | The connection |

**Boards:** ratgdo v2.5i, ratgdo32 and ratgdo32 Disco on ESPHome firmware,
including the dry-contact and Security+ 1.0 variants, and Gelidus Research GRGDO
boards with either ESPHome RATGDO or ESPHome SecplusGDO firmware. Gelidus's
stock configs have no API key, so add one under `api: encryption:` and flash it
first. A board only shows what its firmware has: dry-contact builds have no
light or motion, for example, and only the Disco and Gelidus boards with a
vehicle sensor have vehicle sensing. With the ratgdo encoder fitted, the door's position
comes from the encoder, so `position` is exact rather than estimated from
travel time. The Disco's laser, LED, distance and voltage stay in ESPHome.

The wall button lets rules react to someone using the opener's own button. The
**Push** command only records a press in Hubitat; it never moves the door.

**Toggle** presses the board's own Toggle button. Firmware without one
(SecplusGDO) gets the same effect from the driver: a moving door stops, a closed
door opens and any other door closes. **Refresh** presses Query status where the
firmware has it, and always asks the board for every current state. Settings
such as opening duration or the learn switch stay in the ESPHome dashboard.

## Before you start

You need:

1. **A ratgdo running ESPHome firmware**, with an API encryption key. If it's
   in Home Assistant's ESPHome integration with an "Encrypted" badge, you have
   one. The original ratgdo MQTT firmware and the HomeKit firmware won't work
   with this driver.
2. **Its API key.** This is the `key:` under `api: encryption:` in the
   ratgdo's YAML, a 44-character string ending in `=`. In the ESPHome dashboard,
   open the device's **Edit** page. If you used the ratgdo web installer, the key
   is shown in the ESPHome dashboard after you **Adopt** the device.
3. **Its IP address**, ideally reserved in your router so it never changes.
   Hubitat can't look up `.local` names.
4. **A network path from the hub to the ratgdo on TCP port 6053.** If they're
   on different VLANs, allow it in your firewall.

## Install

### Hubitat Package Manager (recommended)

In [Hubitat Package Manager](https://hubitatpackagemanager.hubitatcommunity.com/),
choose **Install → From a URL** and paste:

```
https://raw.githubusercontent.com/digital-homesteaders/hubitat-ratgdo/main/packageManifest.json
```

### Manually

**Drivers Code → New Driver → Import**, then paste:

```
https://raw.githubusercontent.com/digital-homesteaders/hubitat-ratgdo/main/drivers/ratgdo-esphome.groovy
```

Then **Save**.

### Add your ratgdo

1. **Devices → Add Device → Virtual**. Name it (for example "Garage Door"),
   choose the type **ratgdo (ESPHome)**, then press **Save Device**.
2. On the device page, enter the **IP address** and **API key**, then press
   **Save Preferences**.
3. Within a few seconds, `networkStatus` shows **online** and the door, light and
   sensors fill in.

For a second ratgdo, add another virtual device the same way.

## Troubleshooting

| `networkStatus` / `lastError` | What to do |
|---|---|
| **offline**: "A different ESPHome device ... answers at" | The IP address now belongs to another ESPHome device, often after a DHCP change. Fix the IP (a router reservation stops it happening again), then **Save Preferences**. |
| **bad key**: "Wrong API key" | Copy the key again from the YAML. It must be exact, including the `=` at the end. |
| **bad key**: "no API key set" | The ratgdo runs without encryption. Add `api: encryption: key:` to its YAML and flash it. Generate a key at [esphome.io](https://esphome.io/components/api.html). |
| **offline**: "Can't reach" | Check the IP address, and that the hub can reach port 6053 (VLANs, firewall). |
| **offline**: "didn't finish the encrypted handshake" | Usually another app is holding all of the ratgdo's connections (an ESP8266 allows 4), or the ratgdo is rebooting. |
| Door state looks stale | Press **Refresh**. If `networkStatus` is offline, the driver retries by itself, waiting a little longer each time, up to every 5 minutes. |

For more detail, turn on **Debug logging**. It turns itself off after 30 minutes.

## Reporting a problem

Open an [issue](https://github.com/digital-homesteaders/hubitat-ratgdo/issues)
with your hub model and platform version, the ratgdo board (v2.5, v32 …) and its
ESPHome version (shown in the device's data), plus the debug log. **Never post
your API key.** The driver never logs it, so the log is safe to share.

## Security

The API key is stored as a password-type setting, like other Hubitat apps'
passwords and keys: hidden on screen but not encrypted, so anyone signed in to
the hub can reveal it. Turn on **Hub Login Security** and keep hub backups
private. The key is used only to set up each connection and never crosses the
network. The session keys exist only in memory and are never written
to the hub's database. See [SECURITY.md](SECURITY.md) to report a vulnerability,
and [docs/SPEC.md](docs/SPEC.md) for the protocol and design.

## Credits and licence

MIT, © 2026 Digital Homesteaders. The protocol details come from
[aioesphomeapi](https://github.com/esphome/aioesphomeapi) (MIT) and the
[ratgdo ESPHome config](https://github.com/ratgdo/esphome-ratgdo). See
[NOTICE](NOTICE). ratgdo and ESPHome are the work of their own projects. This
driver isn't affiliated with or endorsed by either.
