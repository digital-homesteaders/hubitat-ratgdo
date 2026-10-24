/**
 * ratgdo (ESPHome) for Hubitat
 *
 * Talks to a ratgdo running ESPHome firmware over the ESPHome native API,
 * encrypted with the device's API key (Noise_NNpsk0_25519_ChaChaPoly_SHA256),
 * the same way Home Assistant does. One device per ratgdo; the light can be a
 * Generic Component Switch child. Design: docs/SPEC.md.
 *
 * Copyright (c) 2026 Digital Homesteaders. MIT licence:
 * https://github.com/digital-homesteaders/hubitat-ratgdo/blob/main/LICENSE
 * Protocol details from aioesphomeapi (MIT), see NOTICE:
 * https://github.com/digital-homesteaders/hubitat-ratgdo/blob/main/NOTICE
 */

import groovy.transform.Field
import hubitat.helper.HexUtils
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.concurrent.ConcurrentHashMap
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

@Field static final String DRIVER_NAME = "ratgdo (ESPHome)"
@Field static final String DRIVER_VERSION = "0.1.0"

// Per-device session: socket phase, Noise keys and nonces, receive buffer and
// entity map. Kept out of state so keys never reach the database.
@Field static final ConcurrentHashMap MEM = new ConcurrentHashMap()
// Per device: attribute -> the value we last sent (see lastValue).
@Field static final ConcurrentHashMap SENT = new ConcurrentHashMap()

@Field static final byte[] NOISE_NAME = "Noise_NNpsk0_25519_ChaChaPoly_SHA256".getBytes("US-ASCII")
@Field static final byte[] PROLOGUE = "NoiseAPIInit\u0000\u0000".getBytes("US-ASCII")
@Field static final BigInteger P25519 = BigInteger.ONE.shiftLeft(255).subtract(19G)
@Field static final BigInteger A24 = 121665G
@Field static final BigInteger P1305 = BigInteger.ONE.shiftLeft(130).subtract(5G)
@Field static final BigInteger CLAMP1305 = new BigInteger("0ffffffc0ffffffc0ffffffc0fffffff", 16)
@Field static final BigInteger MASK128 = BigInteger.ONE.shiftLeft(128).subtract(BigInteger.ONE)

@Field static final int HANDSHAKE_SECS = 15
@Field static final long PING_AFTER_MS = 50000
@Field static final long DEAD_AFTER_MS = 150000
@Field static final int BACKOFF_MAX_SECS = 300
@Field static final int BAD_KEY_RETRY_SECS = 1800
@Field static final int POSITION_STEP = 10
@Field static final int RESTART_SECS = 15

// ESPHome API message types (api.proto)
@Field static final int HELLO_REQ = 1, HELLO_RESP = 2, AUTH_REQ = 3, AUTH_RESP = 4
@Field static final int DISCONNECT_REQ = 5, DISCONNECT_RESP = 6, PING_REQ = 7, PING_RESP = 8
@Field static final int DEVICE_INFO_REQ = 9, DEVICE_INFO_RESP = 10, LIST_REQ = 11, LIST_DONE = 19
@Field static final int SUBSCRIBE_STATES = 20, GET_TIME_REQ = 36, GET_TIME_RESP = 37
@Field static final int COVER_CMD = 30, LIGHT_CMD = 32, LOCK_CMD = 60, BUTTON_CMD = 62
// List-entities response type -> domain, and state response type -> domain
@Field static final Map LIST_TYPES = [12: "binary_sensor", 13: "cover", 15: "light", 16: "sensor", 58: "lock", 61: "button"]
@Field static final Map STATE_TYPES = [21: "binary_sensor", 22: "cover", 24: "light", 25: "sensor", 59: "lock"]

metadata {
    definition(name: "ratgdo (ESPHome)", namespace: "ratgdo", author: "Digital Homesteaders",
               importUrl: "https://raw.githubusercontent.com/digital-homesteaders/hubitat-ratgdo/main/drivers/ratgdo-esphome.groovy",
               singleThreaded: true) {
        capability "Actuator"
        capability "Sensor"
        capability "GarageDoorControl"
        capability "ContactSensor"
        capability "MotionSensor"
        capability "PresenceSensor"
        capability "PushableButton"
        capability "Refresh"
        capability "Initialize"

        attribute "position", "number"
        attribute "light", "enum", ["on", "off"]
        attribute "obstruction", "enum", ["clear", "obstructed"]
        attribute "motor", "enum", ["running", "idle"]
        attribute "remotes", "enum", ["locked", "unlocked"]
        attribute "openings", "number"
        attribute "vehicleMotion", "enum", ["arriving", "leaving", "none"]
        attribute "manuallyOperated", "enum", ["yes", "no"]
        attribute "networkStatus", "enum", ["connecting", "online", "offline", "bad key"]
        attribute "healthStatus", "enum", ["online", "offline"]
        attribute "lastError", "string"

        command "stop"
        command "toggle"
        command "setPosition", [[name: "Position*", type: "NUMBER", description: "0 closed to 100 open"]]
        command "presetPosition", [[name: "Position*", type: "ENUM", description: "Percent open",
                                    constraints: ["0", "25", "50", "75", "100"]]]
        command "lightOn"
        command "lightOff"
        command "lockRemotes"
        command "unlockRemotes"
        command "restart"
    }
    preferences {
        input "host", "text", title: "ratgdo IP address", required: true,
            description: "For example 192.168.1.50. A fixed (reserved) address is best."
        input "apiKey", "password", title: "API encryption key", required: true,
            description: "The 'api: encryption: key:' value from the ratgdo's YAML, also shown in Home Assistant"
        input "port", "text", title: "API port", defaultValue: "6053",
            description: "Leave at 6053 unless the ratgdo's YAML sets another"
        input "lightChild", "bool", title: "Add the light as its own device", defaultValue: true
        input "motionHold", "enum", title: "Motion stays active for", defaultValue: "30",
            options: ["0": "As the ratgdo reports it (about 3 s a pulse)", "30": "30 s after the last motion",
                      "60": "1 minute after the last motion", "120": "2 minutes after the last motion",
                      "300": "5 minutes after the last motion"],
            description: "The ratgdo reports motion as 3-second pulses; holding it avoids a stream of active/inactive events"
        input "txtEnable", "bool", title: "Log door, light and motion changes", defaultValue: true
        input "logEnable", "bool", title: "Debug logging (turns off after 30 minutes)", defaultValue: false
    }
}

// ---------------------------------------------------------------- lifecycle

void installed() { initialize() }

void updated() {
    if (logEnable) runIn(1800, "logsOff")
    device.removeDataValue("esphomeName")   // Save re-learns which ratgdo is at this address
    syncLightChild()
    initialize()
}

/** No motion pulse for the hold time. */
void motionClear() { emit("motion", "inactive") }

void uninstalled() {
    disconnect(true)
    SENT.remove(device.idAsLong)
}

void initialize() {
    disconnect(true)
    state.retry = 0
    state.remove("badKeyWarned")
    unschedule("watchdog")
    if (!host || !apiKey) {
        status("offline", "Enter the ratgdo's IP address and API key, then Save")
        return
    }
    runEvery1Minute("watchdog")
    connectNow()
}

void logsOff() { device.updateSetting("logEnable", [value: "false", type: "bool"]) }

// ---------------------------------------------------------------- commands

void open() { coverPosition(1f) }
void close() { coverPosition(0f) }
void setPosition(def pct) { coverPosition((float) (Math.max(0, Math.min(100, pct as int)) / 100)) }

/** The same as setPosition, from a fixed list (the device page's dropdown). */
void presetPosition(def pct) { setPosition(pct as int) }

void stop() {
    Integer k = keyFor("door")
    if (k != null) sendApi(COVER_CMD, cat(pbFixed32(1, k), pbVarint(8, 1)))
}

void toggle() {
    Integer b = (Integer) MEM[device.idAsLong]?.roles?.get("toggleButton")
    if (b != null) { sendApi(BUTTON_CMD, pbFixed32(1, b)); return }
    String door = device.currentValue("door")
    if (door in ["opening", "closing"]) stop()       // as the opener's own button does
    else if (door == "closed") open()
    else close()
}

/** PushableButton: records a press in Hubitat only. It never moves the door (use Toggle for that). */
void push(def n = 1) { pushed(n as int, "digital") }

private void pushed(int n, String type) {
    if (txtEnable) log.info "${device.displayName} button ${n} was pushed (${type})"
    sendEvent(name: "pushed", value: n, isStateChange: true, type: type, descriptionText: "${device.displayName} button ${n} was pushed")
}

void lightOn() { lightState(true) }
void lightOff() { lightState(false) }
void lockRemotes() { lockCommand(1) }
void unlockRemotes() { lockCommand(0) }

/** Reboot the ratgdo with its own Restart button; the driver reconnects when it's back (about 10 s). */
void restart() {
    Integer k = keyFor("restartButton")
    if (k == null) return
    log.info "${device.displayName}: restarting the ratgdo"
    if (sendApi(BUTTON_CMD, pbFixed32(1, k))) MEM[device.idAsLong].restarting = true
}

/** After our own Restart: no warning, no backoff; reconnect once the board has booted. */
private void reconnectAfterRestart() {
    disconnect()
    status("connecting", "Restarting")
    runIn(RESTART_SECS, "connectNow")
}

void refresh() {
    if (MEM[device.idAsLong] == null && host && apiKey) { connectNow(); return }   // offline: try now
    Integer q = keyFor("queryButton")
    if (q != null) sendApi(BUTTON_CMD, pbFixed32(1, q))
    sendApi(SUBSCRIBE_STATES, new byte[0])
}

void componentOn(cd) { lightOn() }
void componentOff(cd) { lightOff() }
void componentRefresh(cd) { refresh() }

private void coverPosition(float pos) {
    Integer k = keyFor("door")
    if (k != null) sendApi(COVER_CMD, cat(pbFixed32(1, k), pbVarint(4, 1), pbFloat(5, pos)))
}

private void lightState(boolean on) {
    Integer k = keyFor("light")
    if (k != null) sendApi(LIGHT_CMD, cat(pbFixed32(1, k), pbVarint(2, 1), pbVarint(3, on ? 1 : 0)))
}

private void lockCommand(int cmd) {
    Integer k = keyFor("remotes")
    if (k != null) sendApi(LOCK_CMD, cat(pbFixed32(1, k), pbVarint(2, cmd)))
}

private Integer keyFor(String role) {
    Map m = MEM[device.idAsLong]
    Integer k = (Integer) m?.roles?.get(role)
    if (k == null) log.warn "${device.displayName}: not connected, or the ratgdo has no ${role}"
    return k
}

// ---------------------------------------------------------------- connection

void connectNow() {
    disconnect()
    byte[] psk = decodeKey(apiKey as String)
    if (psk == null) {
        badKey("The API key must be the 44-character base64 value from the ratgdo's YAML")
        return
    }
    Integer p = apiPort()
    if (p == null) {
        status("offline", "The API port must be a number from 1 to 65535")
        return
    }
    Map m = [phase: "hello", buf: new byte[0], entities: [:], roles: [:], lastRx: now()]
    MEM[device.idAsLong] = m
    status("connecting", null)
    // New code or a hub restart empties MEM but can leave the old socket open: close it regardless.
    try { interfaces.rawSocket.close() } catch (ignored) { }
    try {
        interfaces.rawSocket.connect([byteInterface: true], host as String, p)
    } catch (e) {
        MEM.remove(device.idAsLong)
        reconnectLater("Can't reach ${host}: ${e.message}")
        return
    }
    m.hs = noiseStart(psk, randomBytes(32))
    byte[] msg1 = (byte[]) m.hs.msg1
    rawSend(cat([1, 0, 0] as byte[], frame([0] as byte[], msg1)))
    runIn(HANDSHAKE_SECS, "handshakeTimeout")
}

void handshakeTimeout() {
    if (MEM[device.idAsLong]?.phase != "ready") reconnectLater("The ratgdo didn't finish the encrypted handshake")
}

void watchdog() {
    Map m = MEM[device.idAsLong]
    // Saving new driver code clears MEM but may leave the socket open: start over.
    if (m == null && device.currentValue("networkStatus") in ["online", "connecting"]) { connectNow(); return }
    if (m?.phase != "ready") return
    long quiet = now() - (long) m.lastRx
    if (quiet > DEAD_AFTER_MS) reconnectLater("No reply from the ratgdo for ${quiet.intdiv(1000)} s")
    else if (quiet > PING_AFTER_MS) sendApi(PING_REQ, new byte[0])
}

void socketStatus(String message) {
    logDebug "socket: ${message}"
    // Only a live session counts: closing an old socket can report late, and the
    // handshake has its own timeout.
    Map m = MEM[device.idAsLong]
    if (m?.phase != "ready") return
    if (m.restarting) reconnectAfterRestart()
    else reconnectLater("Connection lost (${message})")
}

/** The port setting as a number; text, so the hub doesn't show "6,053". Older saves may be numbers. */
private Integer apiPort() {
    String s = (port ?: "6053").toString().replace(",", "").trim()
    return s.isInteger() && (s as int) in 1..65535 ? s as int : null
}

/** Close the session; goodbye sends ESPHome's DisconnectRequest first, which frees the ratgdo's slot at once. */
private void disconnect(boolean goodbye = false) {
    unschedule("handshakeTimeout")
    unschedule("connectNow")
    if (goodbye && MEM[device.idAsLong]?.phase == "ready") {
        try { sendApi(DISCONNECT_REQ, new byte[0]); pauseExecution(200) } catch (ignored) { }   // let it leave before close
    }
    if (MEM.remove(device.idAsLong) != null) {
        try { interfaces.rawSocket.close() } catch (ignored) { }
    }
}

private void reconnectLater(String why) {
    disconnect()
    int n = (state.retry ?: 0) as int
    int secs = Math.min(BACKOFF_MAX_SECS, 5 * (1 << Math.min(n, 6)))
    state.retry = n + 1
    status("offline", why)
    log.warn "${device.displayName}: ${why}; retrying in ${secs} s"
    runIn(secs, "connectNow")
}

/** A problem retrying won't fix soon (wrong key, wrong device): say it once, retry every 30 minutes. */
private void badKey(String why, String s = "bad key") {
    disconnect()
    status(s, why)
    if (!state.badKeyWarned) log.error "${device.displayName}: ${why}"
    state.badKeyWarned = true
    runIn(BAD_KEY_RETRY_SECS, "connectNow")
}

/** Connection state; put() keeps "connecting" then "offline" in one execution from losing the "offline". */
private void status(String s, String error) {
    put("networkStatus", s)
    // Hubitat's standard online/offline; a reconnect in progress keeps the last value.
    String health = s == "online" ? "online" : s == "connecting" ? null : "offline"
    if (health) put("healthStatus", health)
    if (error != null) put("lastError", error)
}

// ---------------------------------------------------------------- receive

void parse(String hex) {
    Map m = MEM[device.idAsLong]
    if (m == null) return
    m.lastRx = now()
    byte[] b = concat((byte[]) m.buf, HexUtils.hexStringToByteArray(hex))
    int pos = 0
    while (b.length - pos >= 3) {
        if (b[pos] != 1) {
            if (b[pos] == 0) badKey("The ratgdo has no API key set (it answered without encryption); add one in its YAML")
            else reconnectLater("Unexpected data from the ratgdo")
            return
        }
        int len = ((b[pos + 1] & 0xff) << 8) | (b[pos + 2] & 0xff)
        if (b.length - pos - 3 < len) break
        byte[] f = slice(b, pos + 3, pos + 3 + len)
        pos += 3 + len
        if (!onFrame(m, f) || !m.is(MEM[device.idAsLong])) return
    }
    m.buf = slice(b, pos, b.length)
}

private boolean onFrame(Map m, byte[] f) {
    switch (m.phase) {
        case "hello":
            if (f.length == 0 || f[0] != 1) {
                // Most likely left over from the previous connection; the handshake timeout covers a real fault.
                logDebug "ignored a ${f.length}-byte frame while waiting for the ratgdo's hello"
                return true
            }
            int end = 1
            while (end < f.length && f[end] != 0) end++
            m.name = new String(f, 1, end - 1, "UTF-8")
            String pinned = device.getDataValue("esphomeName")
            if (pinned && m.name && m.name != pinned) {
                badKey("A different ESPHome device ('${m.name}') answers at ${host}, not '${pinned}'. Fix the IP address, then Save", "offline")
                return false
            }
            m.phase = "handshake"
            return true
        case "handshake":
            if (f.length == 0 || f[0] != 0) {
                String why = f.length > 1 ? new String(f, 1, f.length - 1, "UTF-8") : ""
                if (why == "Handshake MAC failure") badKey("Wrong API key: ${m.name ? "'${m.name}' at " : ""}${host} rejected it")
                else reconnectLater("Handshake refused: ${why}")
                return false
            }
            List keys = noiseFinish((Map) m.hs, slice(f, 1, f.length))
            m.remove("hs")
            if (keys == null) { badKey("Wrong API key: the ratgdo's reply didn't verify"); return false }
            m.tx = keys[0]; m.rx = keys[1]; m.txN = 0L; m.rxN = 0L
            m.phase = "ready"
            unschedule("handshakeTimeout")
            sendApi(HELLO_REQ, cat(pbString(1, "Hubitat ratgdo ${DRIVER_VERSION}"), pbVarint(2, 1), pbVarint(3, 10)),
                    AUTH_REQ, new byte[0])
            return true
        default:
            byte[] p = aeadOpen((byte[]) m.rx, (long) m.rxN, new byte[0], f)
            m.rxN = (long) m.rxN + 1
            if (p == null || p.length < 4) { reconnectLater("A message from the ratgdo didn't decrypt"); return false }
            int type = ((p[0] & 0xff) << 8) | (p[1] & 0xff)
            onMessage(m, type, pbDecode(slice(p, 4, p.length)))
            return true
    }
}

private void onMessage(Map m, int type, Map f) {
    switch (type) {
        case HELLO_RESP:
            sendApi(DEVICE_INFO_REQ, new byte[0], LIST_REQ, new byte[0])
            break
        case AUTH_RESP:
            if (f[1]) badKey("This ratgdo uses an API password, which this driver doesn't support; use an encryption key instead")
            break
        case DISCONNECT_REQ:
            sendApi(DISCONNECT_RESP, new byte[0])
            if (m.restarting) reconnectAfterRestart()
            else reconnectLater("The ratgdo closed the connection")
            break
        case PING_REQ:
            sendApi(PING_RESP, new byte[0])
            break
        case DEVICE_INFO_RESP:
            [2: "esphomeName", 4: "esphomeVersion", 6: "model", 8: "project", 9: "projectVersion", 13: "friendlyName"].each { k, v ->
                if (f[k] != null) device.updateDataValue(v, str(f[k]))
            }
            break
        case LIST_DONE:
            put("numberOfButtons", 1)   // push() works with or without the wall button
            state.retry = 0
            state.remove("badKeyWarned")
            status("online", "none")
            log.info "${device.displayName}: connected (${m.roles.keySet().sort().join(', ')})"
            sendApi(SUBSCRIBE_STATES, new byte[0])
            break
        case GET_TIME_REQ:
            sendApi(GET_TIME_RESP, pbFixed32(1, (int) now().intdiv(1000)))
            break
        default:
            if (LIST_TYPES[type]) onEntity(m, (String) LIST_TYPES[type], f)
            else if (STATE_TYPES[type]) onState(m, f)
    }
}

private void onEntity(Map m, String domain, Map f) {
    Integer key = (Integer) f[2]
    if (key == null) return
    String words = (str(f[1]) + " " + str(f[3])).toLowerCase()
    String role = entityRole(domain, words)
    m.entities[key] = [domain: domain, role: role]
    if (role != null && (m.roles[role] == null || (domain == "cover" && words.contains("garage")))) m.roles[role] = key
    logDebug "entity ${domain} '${str(f[3])}' -> ${role ?: 'ignored'}"
}

/** Which Hubitat role an ESPHome entity plays, from its domain and its object_id and name. */
static String entityRole(String domain, String words) {
    switch (domain) {
        case "cover": return "door"
        case "light": return "light"
        case "lock": return "remotes"
        case "binary_sensor":
            if (words.contains("parked")) return "vehicle"                      // Gelidus ultrasound
            if (words.contains("vehicle")) {
                if (words.contains("detected")) return "vehicle"                // ratgdo32 Disco
                if (words.contains("arriving")) return "arriving"
                if (words.contains("leaving")) return "leaving"
                return null
            }
            if (words.contains("manually")) return "manual"
            if (words.contains("obstruction")) return "obstruction"
            if (words.contains("motion")) return "motion"
            if (words.contains("motor")) return "motor"
            // The opener's wall button: ratgdo's object_id "button", SecplusGDO's "garage_button".
            if (words.tokenize(" ")[0] in ["button", "garage_button", "wall_button"]) return "wallButton"
            return null
        case "sensor": return words.contains("opening") ? "openings" : null
        case "button":
            if (words.contains("toggle")) return "toggleButton"
            if (words.contains("query_status") || words.contains("query status")) return "queryButton"
            if (words.contains("restart") && !words.contains("safe")) return "restartButton"   // never safe mode: no API there
            return null
    }
    return null
}

private void onState(Map m, Map f) {
    Integer key = (Integer) f[1]
    Map e = (Map) m.entities[key]
    if (e?.role == null || m.roles[e.role] != key) return
    switch (e.role) {
        case "door":
            float pos = f[3] != null ? Float.intBitsToFloat((Integer) f[3]) : 0f
            int op = (f[5] ?: 0L) as int
            String door = doorState(pos, op)
            long p = Math.round(pos * 100)
            emit("door", door, door == "open" && pos < 1f ? "${Math.max(1L, Math.min(99L, p))}%" : null)   // "door is open (25%)"
            emit("contact", door == "closed" ? "closed" : "open")
            // About 2 updates a second while moving: report every 10%, then the exact stop.
            if (op == 0 || Math.abs(p - ((lastValue("position") ?: 0) as long)) >= POSITION_STEP) emit("position", p)
            break
        case "light":
            String v = f[2] ? "on" : "off"
            emit("light", v)
            def child = getChildDevice(lightDni())
            if (child) child.parse([[name: "switch", value: v, descriptionText: "${child.displayName} is ${v}"]])
            break
        case "remotes":
            int ls = (f[2] ?: 0L) as int
            if (ls == 1 || ls == 2) emit("remotes", ls == 1 ? "locked" : "unlocked")
            break
        case "motion":
            if (f[3]) break
            int hold = ((settings.motionHold ?: "30") as String) as int
            if (f[2]) {
                emit("motion", "active")
                if (hold > 0) runIn(hold, "motionClear")   // each pulse pushes the end back
            } else if (hold == 0 || device.currentValue("motion") == null) {   // or the first state after connecting
                emit("motion", "inactive")
            }
            break
        case "obstruction":
            if (!f[3]) emit("obstruction", f[2] ? "obstructed" : "clear")
            break
        case "wallButton":
            if (f[3]) break
            boolean down = f[2] ? true : false
            if (down && m.wallDown != true) pushed(1, "physical")    // a press, not the release
            m.wallDown = down
            break
        case "motor":
            if (!f[3]) emit("motor", f[2] ? "running" : "idle")
            break
        case "vehicle":
            if (!f[3]) emit("presence", f[2] ? "present" : "not present")
            break
        case "arriving":
        case "leaving":
            if (f[3]) break
            m[e.role] = f[2] ? true : false
            emit("vehicleMotion", m.arriving ? "arriving" : m.leaving ? "leaving" : "none")
            break
        case "manual":
            if (!f[3]) emit("manuallyOperated", f[2] ? "yes" : "no")
            break
        case "openings":
            if (!f[3] && f[2] != null) emit("openings", Math.round(Float.intBitsToFloat((Integer) f[2])))
            break
    }
}

/** Hubitat door value from ESPHome's cover position (0 closed..1 open) and current operation. */
static String doorState(float pos, int op) {
    if (op == 1) return "opening"
    if (op == 2) return "closing"
    return pos <= 0f ? "closed" : "open"
}

/**
 * What we last sent. Within one execution the hub's currentValue still returns the
 * old value, so "connecting" then "offline" (or two door updates in one burst) would
 * be judged wrongly. SENT outlives sessions; after new code or a reboot it starts
 * empty and currentValue, correct at the start of an execution, fills in.
 */
private def lastValue(String name) {
    Map seen = (Map) SENT[device.idAsLong]
    return seen != null && seen.containsKey(name) ? seen[name] : device.currentValue(name)
}

/** Send an event only when the value really changed; isStateChange so the hub can't drop it on a stale comparison. */
private boolean put(String name, def value, String text = null) {
    if (lastValue(name)?.toString() == value.toString()) return false
    SENT.computeIfAbsent(device.idAsLong) { new ConcurrentHashMap() }.put(name, value)
    sendEvent(name: name, value: value, descriptionText: text, isStateChange: true)
    return true
}

private void emit(String name, def value, String detail = null) {
    String text = "${device.displayName} ${name} is ${value}" + (detail ? " (${detail})" : "")
    if (put(name, value, text) && txtEnable && name in ["door", "light", "motion", "obstruction", "remotes", "presence", "manuallyOperated"]) log.info text
}

// ---------------------------------------------------------------- send

/** Encrypt and send one or more API messages: sendApi(type, body[, type, body...]). */
private boolean sendApi(Object... typeAndBody) {
    Map m = MEM[device.idAsLong]
    if (m?.phase != "ready") { logDebug "not connected; dropped message ${typeAndBody[0]}"; return false }
    ByteArrayOutputStream out = new ByteArrayOutputStream()
    for (int i = 0; i < typeAndBody.length; i += 2) {
        int type = (int) typeAndBody[i]
        byte[] body = (byte[]) typeAndBody[i + 1]
        byte[] plain = [type >> 8, type, body.length >> 8, body.length] as byte[]
        byte[] ct = aeadSeal((byte[]) m.tx, (long) m.txN, new byte[0], concat(plain, body))
        m.txN = (long) m.txN + 1
        out.write(frame(new byte[0], ct))
    }
    rawSend(out.toByteArray())
    return true
}

private static byte[] frame(byte[] prefix, byte[] payload) {
    int len = prefix.length + payload.length
    return concat([1, len >> 8, len] as byte[], concat(prefix, payload))
}

private void rawSend(byte[] b) {
    interfaces.rawSocket.sendMessage(HexUtils.byteArrayToHexString(b))
}

// ---------------------------------------------------------------- light child

private String lightDni() { "${device.deviceNetworkId}-light" }

private void syncLightChild() {
    def child = getChildDevice(lightDni())
    if (lightChild != false && !child) {
        addChildDevice("hubitat", "Generic Component Switch", lightDni(),
            [name: "${device.displayName} Light", isComponent: true])
    } else if (lightChild == false && child) {
        deleteChildDevice(lightDni())
    }
}

private void logDebug(String msg) { if (logEnable) log.debug "${device.displayName}: ${msg}" }

// ---------------------------------------------------------------- protobuf

static byte[] pbVarint(int field, long v) {
    ByteArrayOutputStream out = new ByteArrayOutputStream()
    writeVarint(out, (field << 3) as long)
    writeVarint(out, v)
    return out.toByteArray()
}

static byte[] pbFixed32(int field, int v) {
    return [(field << 3) | 5, v, v >> 8, v >> 16, v >> 24] as byte[]
}

static byte[] pbFloat(int field, float v) { pbFixed32(field, Float.floatToIntBits(v)) }

static byte[] pbString(int field, String s) {
    byte[] b = s.getBytes("UTF-8")
    ByteArrayOutputStream out = new ByteArrayOutputStream()
    writeVarint(out, ((field << 3) | 2) as long)
    writeVarint(out, b.length as long)
    out.write(b)
    return out.toByteArray()
}

private static void writeVarint(ByteArrayOutputStream out, long v) {
    while ((v & ~0x7fL) != 0) {
        out.write((int) ((v & 0x7f) | 0x80))
        v >>>= 7
    }
    out.write((int) v)
}

/** Decode a protobuf message into field number -> value: Long (varint, fixed64), Integer (fixed32) or byte[]. Last one wins. */
static Map pbDecode(byte[] b) {
    Map f = [:]
    int i = 0
    while (i < b.length) {
        long tag = 0; int shift = 0
        while (true) { int c = b[i++] & 0xff; tag |= ((long) (c & 0x7f)) << shift; shift += 7; if (c < 0x80) break }
        int field = (int) (tag >>> 3)
        switch ((int) (tag & 7)) {
            case 0:
                long v = 0; shift = 0
                while (true) { int c = b[i++] & 0xff; v |= ((long) (c & 0x7f)) << shift; shift += 7; if (c < 0x80) break }
                f[field] = v
                break
            case 1:
                long v8 = 0
                for (int j = 7; j >= 0; j--) v8 = (v8 << 8) | (b[i + j] & 0xff)
                f[field] = v8; i += 8
                break
            case 2:
                long len = 0; shift = 0
                while (true) { int c = b[i++] & 0xff; len |= ((long) (c & 0x7f)) << shift; shift += 7; if (c < 0x80) break }
                f[field] = slice(b, i, i + (int) len); i += (int) len
                break
            case 5:
                f[field] = (b[i] & 0xff) | ((b[i + 1] & 0xff) << 8) | ((b[i + 2] & 0xff) << 16) | ((b[i + 3] & 0xff) << 24)
                i += 4
                break
            default:
                return f   // groups are never used by ESPHome
        }
    }
    return f
}

private static String str(def v) { v instanceof byte[] ? new String((byte[]) v, "UTF-8") : (v == null ? "" : v.toString()) }

// ---------------------------------------------------------------- Noise_NNpsk0_25519_ChaChaPoly_SHA256 (initiator)

/** Message 1 (psk, e). Returns the handshake state with msg1 to send. */
static Map noiseStart(byte[] psk, byte[] ePriv) {
    byte[] h = sha256(NOISE_NAME)
    byte[] ck = h
    h = sha256(concat(h, PROLOGUE))
    List o = hkdf(ck, psk, 3)                       // MixKeyAndHash(psk)
    ck = (byte[]) o[0]; h = sha256(concat(h, (byte[]) o[1]))
    byte[] ePub = x25519(ePriv, basePoint())
    h = sha256(concat(h, ePub))                     // e: MixHash, then MixKey (psk handshake)
    o = hkdf(ck, ePub, 2)
    ck = (byte[]) o[0]
    byte[] tag = aeadSeal((byte[]) o[1], 0L, h, new byte[0])  // EncryptAndHash("")
    h = sha256(concat(h, tag))
    return [h: h, ck: ck, e: ePriv, msg1: concat(ePub, tag)]
}

/** Message 2 (e, ee). Returns [sendKey, receiveKey], or null if the key doesn't match. */
static List noiseFinish(Map hs, byte[] msg2) {
    if (msg2.length < 48) return null
    byte[] re = slice(msg2, 0, 32)
    byte[] h = sha256(concat((byte[]) hs.h, re))
    List o = hkdf((byte[]) hs.ck, re, 2)
    o = hkdf((byte[]) o[0], x25519((byte[]) hs.e, re), 2)
    byte[] ck = (byte[]) o[0]
    byte[] rest = slice(msg2, 32, msg2.length)
    if (aeadOpen((byte[]) o[1], 0L, h, rest) == null) return null
    o = hkdf(ck, new byte[0], 2)                    // Split()
    return [o[0], o[1]]
}

static byte[] sha256(byte[] b) { MessageDigest.getInstance("SHA-256").digest(b) }

static byte[] hmac(byte[] key, byte[] data) {
    Mac mac = Mac.getInstance("HmacSHA256")
    mac.init(new SecretKeySpec(key, "HmacSHA256"))
    return mac.doFinal(data)
}

/** Noise HKDF: two or three 32-byte outputs. */
static List hkdf(byte[] ck, byte[] ikm, int n) {
    byte[] tk = hmac(ck, ikm)
    byte[] o1 = hmac(tk, [1] as byte[])
    byte[] o2 = hmac(tk, concat(o1, [2] as byte[]))
    return n == 2 ? [o1, o2] : [o1, o2, hmac(tk, concat(o2, [3] as byte[]))]
}

// ---------------------------------------------------------------- X25519 (RFC 7748)

static byte[] basePoint() { byte[] u = new byte[32]; u[0] = 9; return u }

static byte[] x25519(byte[] k, byte[] u) {
    byte[] kk = slice(k, 0, 32)
    kk[0] = (byte) (kk[0] & 248); kk[31] = (byte) ((kk[31] & 127) | 64)
    byte[] uu = slice(u, 0, 32)
    uu[31] = (byte) (uu[31] & 127)
    BigInteger scalar = leToBig(kk)
    BigInteger p = P25519
    BigInteger x1 = leToBig(uu).mod(p)
    BigInteger x2 = BigInteger.ONE, z2 = BigInteger.ZERO, x3 = x1, z3 = BigInteger.ONE
    boolean swap = false
    for (int t = 254; t >= 0; t--) {
        boolean kt = scalar.testBit(t)
        if (swap != kt) { BigInteger s = x2; x2 = x3; x3 = s; s = z2; z2 = z3; z3 = s }
        swap = kt
        BigInteger a = x2.add(z2), aa = a.multiply(a).mod(p)
        BigInteger b = x2.subtract(z2), bb = b.multiply(b).mod(p)
        BigInteger e = aa.subtract(bb)
        BigInteger c = x3.add(z3), d = x3.subtract(z3)
        BigInteger da = d.multiply(a).mod(p), cb = c.multiply(b).mod(p)
        BigInteger s1 = da.add(cb), s2 = da.subtract(cb)
        x3 = s1.multiply(s1).mod(p)
        z3 = x1.multiply(s2.multiply(s2).mod(p)).mod(p)
        x2 = aa.multiply(bb).mod(p)
        z2 = e.multiply(aa.add(A24.multiply(e))).mod(p)
    }
    if (swap) { x2 = x3; z2 = z3 }
    return bigToLe(x2.multiply(z2.modPow(p.subtract(2G), p)).mod(p), 32)
}

private static BigInteger leToBig(byte[] b) {
    byte[] be = new byte[b.length]
    for (int i = 0; i < b.length; i++) be[i] = b[b.length - 1 - i]
    return new BigInteger(1, be)
}

private static byte[] bigToLe(BigInteger v, int len) {
    byte[] be = v.toByteArray()
    byte[] out = new byte[len]
    for (int i = 0; i < len && i < be.length; i++) out[i] = be[be.length - 1 - i]
    return out
}

// ---------------------------------------------------------------- ChaCha20-Poly1305 (RFC 8439)

/** Noise nonce: 4 zero bytes then the 64-bit counter, little-endian. */
private static byte[] noiseNonce(long n) {
    byte[] b = new byte[12]
    for (int i = 0; i < 8; i++) b[4 + i] = (byte) (n >>> (8 * i))
    return b
}

static byte[] aeadSeal(byte[] key, long n, byte[] ad, byte[] plain) {
    byte[] nonce = noiseNonce(n)
    byte[] ct = chacha20(key, 1, nonce, plain)
    return concat(ct, polyTag(key, nonce, ad, ct))
}

/** Returns the plaintext, or null if the tag doesn't verify. */
static byte[] aeadOpen(byte[] key, long n, byte[] ad, byte[] sealed) {
    if (sealed.length < 16) return null
    byte[] nonce = noiseNonce(n)
    byte[] ct = slice(sealed, 0, sealed.length - 16)
    byte[] tag = slice(sealed, sealed.length - 16, sealed.length)
    if (!MessageDigest.isEqual(tag, polyTag(key, nonce, ad, ct))) return null
    return chacha20(key, 1, nonce, ct)
}

private static byte[] polyTag(byte[] key, byte[] nonce, byte[] ad, byte[] ct) {
    byte[] otk = slice(chachaBlock(key, 0, nonce), 0, 32)
    ByteArrayOutputStream mac = new ByteArrayOutputStream()
    mac.write(ad); mac.write(new byte[(16 - ad.length % 16) % 16])
    mac.write(ct); mac.write(new byte[(16 - ct.length % 16) % 16])
    mac.write(le64(ad.length)); mac.write(le64(ct.length))
    return poly1305(otk, mac.toByteArray())
}

static byte[] poly1305(byte[] key, byte[] msg) {
    BigInteger r = leToBig(slice(key, 0, 16)).and(CLAMP1305)
    BigInteger s = leToBig(slice(key, 16, 32))
    BigInteger acc = BigInteger.ZERO
    for (int i = 0; i < msg.length; i += 16) {
        int end = Math.min(i + 16, msg.length)
        byte[] blk = new byte[end - i + 1]
        for (int j = i; j < end; j++) blk[j - i] = msg[j]
        blk[end - i] = 1
        acc = acc.add(leToBig(blk)).multiply(r).mod(P1305)
    }
    return bigToLe(acc.add(s).and(MASK128), 16)
}

private static byte[] le64(long v) {
    byte[] b = new byte[8]
    for (int i = 0; i < 8; i++) b[i] = (byte) (v >>> (8 * i))
    return b
}

static byte[] chacha20(byte[] key, int counter, byte[] nonce, byte[] data) {
    byte[] out = new byte[data.length]
    for (int off = 0; off < data.length; off += 64) {
        byte[] ks = chachaBlock(key, counter++, nonce)
        int n = Math.min(64, data.length - off)
        for (int i = 0; i < n; i++) out[off + i] = (byte) (data[off + i] ^ ks[i])
    }
    return out
}

static byte[] chachaBlock(byte[] key, int counter, byte[] nonce) {
    int[] s = new int[16]
    s[0] = 0x61707865; s[1] = 0x3320646e; s[2] = 0x79622d32; s[3] = 0x6b206574
    for (int i = 0; i < 8; i++) s[4 + i] = le32(key, 4 * i)
    s[12] = counter
    for (int i = 0; i < 3; i++) s[13 + i] = le32(nonce, 4 * i)
    int[] x = new int[16]
    for (int i = 0; i < 16; i++) x[i] = s[i]
    for (int i = 0; i < 10; i++) {
        qr(x, 0, 4, 8, 12); qr(x, 1, 5, 9, 13); qr(x, 2, 6, 10, 14); qr(x, 3, 7, 11, 15)
        qr(x, 0, 5, 10, 15); qr(x, 1, 6, 11, 12); qr(x, 2, 7, 8, 13); qr(x, 3, 4, 9, 14)
    }
    byte[] out = new byte[64]
    for (int i = 0; i < 16; i++) {
        int v = x[i] + s[i]
        out[4 * i] = (byte) v; out[4 * i + 1] = (byte) (v >>> 8)
        out[4 * i + 2] = (byte) (v >>> 16); out[4 * i + 3] = (byte) (v >>> 24)
    }
    return out
}

private static void qr(int[] x, int a, int b, int c, int d) {
    int t
    x[a] += x[b]; t = x[d] ^ x[a]; x[d] = (t << 16) | (t >>> 16)
    x[c] += x[d]; t = x[b] ^ x[c]; x[b] = (t << 12) | (t >>> 20)
    x[a] += x[b]; t = x[d] ^ x[a]; x[d] = (t << 8) | (t >>> 24)
    x[c] += x[d]; t = x[b] ^ x[c]; x[b] = (t << 7) | (t >>> 25)
}

private static int le32(byte[] b, int i) {
    (b[i] & 0xff) | ((b[i + 1] & 0xff) << 8) | ((b[i + 2] & 0xff) << 16) | ((b[i + 3] & 0xff) << 24)
}

// ---------------------------------------------------------------- bytes

static byte[] decodeKey(String key) {
    try {
        byte[] b = (key ?: "").trim().decodeBase64()
        return b.length == 32 ? b : null
    } catch (e) {
        return null
    }
}

private static byte[] randomBytes(int n) {
    byte[] b = new byte[n]
    new SecureRandom().nextBytes(b)
    return b
}

static byte[] cat(byte[]... parts) {
    ByteArrayOutputStream out = new ByteArrayOutputStream()
    parts.each { out.write(it) }
    return out.toByteArray()
}

static byte[] concat(byte[] a, byte[] b) {
    byte[] out = new byte[a.length + b.length]
    for (int i = 0; i < a.length; i++) out[i] = a[i]
    for (int i = 0; i < b.length; i++) out[a.length + i] = b[i]
    return out
}

static byte[] slice(byte[] b, int from, int to) {
    byte[] out = new byte[to - from]
    for (int i = from; i < to; i++) out[i - from] = b[i]
    return out
}
