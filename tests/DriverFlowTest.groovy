/**
 * The driver against a fake ratgdo that does the device side of the ESPHome
 * Noise handshake and API, with frames delivered whole, byte by byte, and
 * joined together. Covers connect, entity mapping, states, every command's
 * bytes, ping, get time, disconnect, wrong key, plaintext devices, timeouts,
 * backoff and the light child.
 */

import groovy.transform.Field
import static Check.check

File root = new File(getClass().protectionDomain.codeSource.location.path).parentFile.parentFile
String KEY = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA="

/** The device side of the ESPHome native API, built on the driver's own (separately verified) primitives. */
class FakeRatgdo {
    Class d
    byte[] psk
    boolean wrongKey, plaintext, silent
    String serverName = "nexus-gate"
    byte[] rxBuf = new byte[0]
    boolean gotHello
    Map hs
    byte[] tx, rx
    long txN, rxN
    List<List> received = []      // [type, fields]
    Map<Integer, List> entities = [:]   // key -> [type, body]
    List<List> initialStates = []   // [type, body], encrypted when sent

    static final byte[] NAME = "Noise_NNpsk0_25519_ChaChaPoly_SHA256".bytes
    static final byte[] PROLOGUE = "NoiseAPIInit\u0000\u0000".bytes

    byte[] cat(byte[]... parts) { parts.inject(new byte[0]) { a, b -> d.concat(a, b) } }
    byte[] frame(byte[] p) { cat([1, p.length >> 8, p.length] as byte[], p) }

    /** Bytes from the driver in; bytes for the driver out. */
    byte[] receive(byte[] data) {
        rxBuf = cat(rxBuf, data)
        ByteArrayOutputStream out = new ByteArrayOutputStream()
        while (rxBuf.length >= 3) {
            int len = ((rxBuf[1] & 0xff) << 8) | (rxBuf[2] & 0xff)
            if (rxBuf.length < 3 + len) break
            byte[] f = d.slice(rxBuf, 3, 3 + len)
            rxBuf = d.slice(rxBuf, 3 + len, rxBuf.length)
            out.write(onFrame(f))
        }
        return out.toByteArray()
    }

    byte[] onFrame(byte[] f) {
        if (silent) return new byte[0]
        if (f.length == 0) { gotHello = true; tx = rx = null; txN = rxN = 0; return new byte[0] }   // a new connection
        assert gotHello
        if (tx == null) return handshake(f)
        byte[] p = d.aeadOpen(rx, rxN++, new byte[0], f)
        assert p != null
        int type = ((p[0] & 0xff) << 8) | (p[1] & 0xff)
        Map fields = d.pbDecode(d.slice(p, 4, p.length))
        received << [type, fields]
        return respond(type)
    }

    byte[] handshake(byte[] f) {
        if (plaintext) return [0, 0, 2, 0x0a, 0] as byte[]
        assert f[0] == 0
        byte[] msg1 = d.slice(f, 1, f.length)
        byte[] h = d.sha256(NAME), ck = h
        h = d.sha256(cat(h, PROLOGUE))
        List o = d.hkdf(ck, psk, 3); ck = o[0]; h = d.sha256(cat(h, o[1]))
        byte[] re = d.slice(msg1, 0, 32)
        h = d.sha256(cat(h, re)); o = d.hkdf(ck, re, 2); ck = o[0]
        byte[] tag1 = d.slice(msg1, 32, 48)
        byte[] hello = frame(cat([1] as byte[], (serverName + "\u0000BCFF4D901148\u0000").bytes))
        if (wrongKey || d.aeadOpen(o[1], 0L, h, tag1) == null) {
            return cat(hello, frame(cat([1] as byte[], "Handshake MAC failure".bytes)))
        }
        h = d.sha256(cat(h, tag1))
        byte[] e = new byte[32]; e[5] = 42
        byte[] ePub = d.x25519(e, d.basePoint())
        h = d.sha256(cat(h, ePub)); o = d.hkdf(ck, ePub, 2); ck = o[0]
        o = d.hkdf(ck, d.x25519(e, re), 2); ck = o[0]
        byte[] tag2 = d.aeadSeal(o[1], 0L, h, new byte[0])
        o = d.hkdf(ck, new byte[0], 2)
        rx = o[0]; tx = o[1]
        return cat(hello, frame(cat([0] as byte[], ePub, tag2)))
    }

    /** An encrypted API message for the driver. */
    byte[] msg(int type, byte[] body) {
        byte[] plain = cat([type >> 8, type, body.length >> 8, body.length] as byte[], body)
        return frame(d.aeadSeal(tx, txN++, new byte[0], plain))
    }

    byte[] respond(int type) {
        switch (type) {
            case 1: return msg(2, cat(d.pbVarint(1, 1), d.pbVarint(2, 19), d.pbString(3, "2026.10.0"), d.pbString(4, "nexus-gate")))
            case 9: return msg(10, cat(d.pbString(2, serverName), d.pbString(3, "BC:FF:4D:90:11:48"), d.pbString(4, "2026.10.0"),
                                       d.pbString(6, "esp8266"), d.pbString(8, "ratgdo.esphome"), d.pbString(9, "v25iboard"), d.pbString(13, "Nexus Gate")))
            case 11:
                ByteArrayOutputStream out = new ByteArrayOutputStream()
                entities.each { k, v -> out.write(msg(v[0] as int, v[1] as byte[])) }
                out.write(msg(19, new byte[0]))
                return out.toByteArray()
            case 20:
                ByteArrayOutputStream out = new ByteArrayOutputStream()
                initialStates.each { out.write(msg(it[0] as int, it[1] as byte[])) }
                return out.toByteArray()
        }
        return new byte[0]
    }
}

// Entity keys, as a real ratgdo's list would have them.
@Field int DOOR = 0x1001
@Field int LIGHT = 0x1002
@Field int LOCK = 0x1003
@Field int MOTION = 0x1004
@Field int OBST = 0x1005
@Field int MOTOR = 0x1006
@Field int BTN_SENSOR = 0x1007
@Field int DRY = 0x1008
@Field int OPENINGS = 0x1009
@Field int PAIRED = 0x100a
@Field int TOGGLE = 0x100b
@Field int QUERY = 0x100c
@Field int QUERY_OPENINGS = 0x100d
@Field int RESTART = 0x100e
@Field int LEARN = 0x100f

class World {
    Hub hub
    FakeDevice dev
    FakeRatgdo rat
    Class d
    int chunk = 0          // 0: whole; n: deliver in n-byte pieces
    boolean joined         // hold replies and deliver them together

    byte[] h(String s) { s.decodeHex() }

    /** Move bytes back and forth until both sides are quiet. */
    void pump() {
        FakeRawSocket sock = dev.driver.interfaces.rawSocket
        int guard = 0
        while (sock.sent && guard++ < 50) {
            List<String> out = new ArrayList(sock.sent); sock.sent.clear()
            ByteArrayOutputStream replies = new ByteArrayOutputStream()
            out.each { replies.write(rat.receive(h(it))) }
            deliver(replies.toByteArray())
            hub.settle()
        }
    }

    void deliver(byte[] b) {
        if (b.length == 0) return
        if (chunk == 0) { dev.parse(b.encodeHex().toString()); return }
        for (int i = 0; i < b.length; i += chunk) dev.parse(d.slice(b, i, Math.min(b.length, i + chunk)).encodeHex().toString())
    }

    /** The device sends one API message on its own. */
    void push(int type, byte[] body) { deliver(rat.msg(type, body)); hub.settle(); pump() }

    List lastSent(int type) { rat.received.reverse().find { it[0] == type } }
    List sentTypes() { rat.received.collect { it[0] } }
}

World world(File root, String key, Map opts = [:]) {
    World w = new World()
    w.hub = new Hub(root)
    w.dev = w.hub.device("ratgdo (ESPHome)", "ratgdo-1", [label: "Nexus Gate"])
    w.d = w.dev.driver.getClass()
    w.rat = new FakeRatgdo(d: w.d, psk: key.decodeBase64())
    Class d = w.d
    def ent = { int type, int k, String objId, String name, byte[] extra = new byte[0] ->
        w.rat.entities[k] = [type, d.concat(d.concat(d.concat(d.pbString(1, objId), d.pbFixed32(2, k)), d.pbString(3, name)), extra)]
    }
    ent(13, DOOR, "door", "Door", d.pbString(8, "garage"))
    ent(15, LIGHT, "light", "Light")
    ent(58, LOCK, "lock_remotes", "Lock remotes")
    ent(12, MOTION, "motion", "Motion", d.pbString(5, "motion"))
    ent(12, OBST, "obstruction", "Obstruction", d.pbString(5, "problem"))
    ent(12, MOTOR, "motor", "Motor", d.pbString(5, "running"))
    ent(12, BTN_SENSOR, "button", "Button")
    ent(12, DRY, "dry_contact_open", "Dry contact open")
    ent(16, OPENINGS, "openings", "Openings")
    ent(16, PAIRED, "paired_devices", "Paired Devices")
    ent(61, TOGGLE, "toggle_door", "Toggle door")
    ent(61, QUERY, "query_status", "Query status")
    ent(61, QUERY_OPENINGS, "query_openings", "Query openings")
    ent(61, RESTART, "restart", "Restart")
    ent(17, LEARN, "learn", "Learn")
    w.rat.initialStates = [
        [22, d.pbFixed32(1, DOOR)],                                   // closed, idle: zeros left out
        [24, d.pbFixed32(1, LIGHT)],
        [59, d.concat(d.pbFixed32(1, LOCK), d.pbVarint(2, 2))],
        [21, d.pbFixed32(1, MOTION)],
        [21, d.pbFixed32(1, OBST)],
        [21, d.pbFixed32(1, MOTOR)],
        [21, d.concat(d.pbFixed32(1, DRY), d.pbVarint(2, 1))],
        [25, d.concat(d.pbFixed32(1, OPENINGS), d.pbFloat(2, 1234f))],
        [25, d.concat(d.pbFixed32(1, PAIRED), d.pbFloat(2, 3f))],
    ]
    w.chunk = opts.chunk ?: 0
    w.dev.driver.settings.host = "172.16.214.150"
    w.dev.driver.settings.apiKey = key
    return w
}

World connected(File root, String key, Map opts = [:]) {
    World w = world(root, key, opts)
    w.dev.updated()
    w.hub.settle()
    w.pump()
    return w
}

check("connects: socket, encrypted handshake, hello with the empty login, device info, entities, states") {
    World w = connected(root, KEY)
    def c = w.dev.driver.callsNamed("socket.connect")[0]
    assert c[1] == "172.16.214.150" && c[2] == 6053 && c[3] == [byteInterface: true]
    assert w.sentTypes() == [1, 3, 9, 11, 20]
    assert new String(w.rat.received[0][1][1] as byte[], "UTF-8").startsWith("Hubitat ratgdo")
    assert w.rat.received[0][1][2] == 1L && w.rat.received[0][1][3] == 10L
    assert w.dev.current.networkStatus == "online" && w.dev.current.lastError == "none"
    assert w.dev.data.friendlyName == "Nexus Gate" && w.dev.data.esphomeVersion == "2026.10.0" && w.dev.data.model == "esp8266"
    assert !w.dev.data.values().any { it.contains("BC:FF") }, "the MAC address is not kept"
    assert w.dev.current.subMap(["door", "contact", "position", "light", "remotes", "motion", "obstruction", "motor", "openings"]) ==
        [door: "closed", contact: "closed", position: 0L, light: "off", remotes: "unlocked", motion: "inactive",
         obstruction: "clear", motor: "idle", openings: 1234L]
    assert w.dev.driver.log.at("info").any { it.contains("connected") }
    assert w.dev.driver.callsNamed("runEvery1Minute") == [["runEvery1Minute", "watchdog"]]
}

check("frames arriving one byte at a time, or a few at once, give the same result") {
    [1, 2, 7, 1000].each { n ->
        World w = connected(root, KEY, [chunk: n])
        assert w.dev.current.networkStatus == "online" && w.dev.current.door == "closed" && w.dev.current.openings == 1234L, "chunk ${n}"
    }
}

check("entities map by domain and name; unrelated ones are ignored") {
    World w = connected(root, KEY)
    Map m = w.d.MEM[w.dev.idAsLong]
    assert m.roles == [door: DOOR, light: LIGHT, remotes: LOCK, motion: MOTION, obstruction: OBST, motor: MOTOR,
                       wallButton: BTN_SENSOR, openings: OPENINGS, toggleButton: TOGGLE, queryButton: QUERY]
    assert w.d.entityRole("binary_sensor", "dry_contact_open dry contact open") == null
    assert w.d.entityRole("sensor", "paired_devices_total paired devices") == null
    assert w.d.entityRole("button", "query_openings query openings") == null
    assert w.d.entityRole("switch", "learn learn") == null
}

check("door states: opening, closing, partly open, open, back to closed") {
    World w = connected(root, KEY)
    Class d = w.d
    def door = { float pos, int op -> w.push(22, d.concat(d.concat(d.pbFixed32(1, DOOR), d.pbFloat(3, pos)), d.pbVarint(5, op))) }
    door(0.1f, 1); assert w.dev.current.door == "opening" && w.dev.current.contact == "open" && w.dev.current.position == 10L
    door(0.4f, 0); assert w.dev.current.door == "open" && w.dev.current.position == 40L
    door(1f, 0);   assert w.dev.current.door == "open" && w.dev.current.position == 100L
    door(0.9f, 2); assert w.dev.current.door == "closing" && w.dev.current.contact == "open"
    door(0f, 0);   assert w.dev.current.door == "closed" && w.dev.current.contact == "closed" && w.dev.current.position == 0L
    assert w.dev.driver.log.at("info").count { it.contains("door is") } == 5
}

check("sensor states: light, motion, obstruction, motor, remotes, openings; missing states are skipped") {
    World w = connected(root, KEY)
    Class d = w.d
    w.push(24, d.concat(d.pbFixed32(1, LIGHT), d.pbVarint(2, 1)))
    w.push(21, d.concat(d.pbFixed32(1, MOTION), d.pbVarint(2, 1)))
    w.push(21, d.concat(d.pbFixed32(1, OBST), d.pbVarint(2, 1)))
    w.push(21, d.concat(d.pbFixed32(1, MOTOR), d.pbVarint(2, 1)))
    w.push(59, d.concat(d.pbFixed32(1, LOCK), d.pbVarint(2, 1)))
    w.push(25, d.concat(d.pbFixed32(1, OPENINGS), d.pbFloat(2, 1235f)))
    assert w.dev.current.subMap(["light", "motion", "obstruction", "motor", "remotes", "openings"]) ==
        [light: "on", motion: "active", obstruction: "obstructed", motor: "running", remotes: "locked", openings: 1235L]
    w.push(21, d.concat(d.concat(d.pbFixed32(1, MOTION), d.pbVarint(2, 0)), d.pbVarint(3, 1)))   // missing_state
    w.push(59, d.concat(d.pbFixed32(1, LOCK), d.pbVarint(2, 4)))                                 // locking: no change
    w.push(21, d.concat(d.pbFixed32(1, 0x7777), d.pbVarint(2, 1)))                               // unknown key
    assert w.dev.current.motion == "active" && w.dev.current.remotes == "locked"
}

check("unchanged values send no new events") {
    World w = connected(root, KEY)
    int n = w.dev.events.size()
    w.push(22, w.d.pbFixed32(1, DOOR))
    w.push(24, w.d.pbFixed32(1, LIGHT))
    assert w.dev.events.size() == n
}

check("commands: the exact API message for each") {
    World w = connected(root, KEY)
    def last = { int type -> w.dev.driver.hub.settle(); w.pump(); w.lastSent(type)[1] }
    w.dev.open();  Map f = last(30); assert f[1] == DOOR && f[4] == 1L && Float.intBitsToFloat(f[5]) == 1f
    w.dev.close(); f = last(30); assert f[4] == 1L && Float.intBitsToFloat(f[5]) == 0f
    w.dev.setPosition(37); f = last(30); assert Math.abs(Float.intBitsToFloat(f[5]) - 0.37f) < 1e-6
    w.dev.setPosition(150); f = last(30); assert Float.intBitsToFloat(f[5]) == 1f
    w.dev.presetPosition("25"); f = last(30); assert Float.intBitsToFloat(f[5]) == 0.25f
    w.dev.presetPosition("0"); f = last(30); assert Float.intBitsToFloat(f[5]) == 0f
    w.dev.stop(); f = last(30); assert f[1] == DOOR && f[8] == 1L && f[4] == null
    w.dev.toggle(); f = last(62); assert f[1] == TOGGLE
    w.dev.lightOn(); f = last(32); assert f[1] == LIGHT && f[2] == 1L && f[3] == 1L
    w.dev.lightOff(); f = last(32); assert f[2] == 1L && f[3] == 0L
    w.dev.lockRemotes(); f = last(60); assert f[1] == LOCK && f[2] == 1L
    w.dev.unlockRemotes(); f = last(60); assert f[1] == LOCK && (f[2] ?: 0L) == 0L
    int before = w.rat.received.size()
    w.dev.refresh(); w.pump()
    assert w.rat.received.drop(before).collect { it[0] } == [62, 20] && w.rat.received[before][1][1] == QUERY
}

check("toggle without the ratgdo's Toggle button opens a closed door and closes any other") {
    World w = world(root, KEY)
    w.rat.entities.remove(TOGGLE)
    w.dev.updated(); w.hub.settle(); w.pump()
    w.dev.toggle(); w.pump(); assert Float.intBitsToFloat(w.lastSent(30)[1][5]) == 1f
    w.push(22, w.d.concat(w.d.pbFixed32(1, DOOR), w.d.pbFloat(3, 1f)))
    w.dev.toggle(); w.pump(); assert Float.intBitsToFloat(w.lastSent(30)[1][5]) == 0f
}

check("the light child: created on Save, follows the light, and its switch drives the light") {
    World w = connected(root, KEY)
    FakeDevice child = w.dev.driver.getChildDevice("ratgdo-1-light")
    assert child && w.dev.driver.callsNamed("addChildDevice")[0][1..2] == ["hubitat", "Generic Component Switch"]
    w.push(24, w.d.concat(w.d.pbFixed32(1, LIGHT), w.d.pbVarint(2, 1)))
    assert child.current.switch == "on"
    child.off(); w.pump()
    assert w.lastSent(32)[1][3] == 0L
    w.dev.driver.settings.lightChild = false
    w.dev.updated(); w.hub.settle(); w.pump()
    assert !w.dev.driver.getChildDevice("ratgdo-1-light")
    assert w.dev.current.networkStatus == "online"
}

check("ping and get time from the ratgdo are answered") {
    World w = connected(root, KEY)
    w.push(7, new byte[0])
    assert w.sentTypes().last() == 8
    w.push(36, new byte[0])
    assert w.sentTypes().last() == 37
    long epoch = (w.lastSent(37)[1][1] as int) & 0xffffffffL
    assert Math.abs(epoch - System.currentTimeMillis().intdiv(1000)) < 5
}

check("a disconnect request is acknowledged and the driver reconnects in 5 s") {
    World w = connected(root, KEY)
    w.push(5, new byte[0])
    assert w.sentTypes().last() == 6
    assert w.dev.current.networkStatus == "offline"
    assert w.dev.driver.callsNamed("runIn").last()[1..2] == [5, "connectNow"]
    w.dev.driver.callsNamed("socket.close")
    w.rat = new FakeRatgdo(d: w.d, psk: KEY.decodeBase64(), entities: w.rat.entities)
    w.dev.connectNow(); w.hub.settle(); w.pump()
    assert w.dev.current.networkStatus == "online" && w.dev.driver.state.retry == 0
}

check("a wrong key: 'bad key', one error in the log, retry in 30 minutes, nothing sent after the handshake") {
    World w = world(root, KEY)
    w.rat.wrongKey = true
    w.dev.updated(); w.hub.settle(); w.pump()
    assert w.dev.current.networkStatus == "bad key" && w.dev.current.lastError.contains("Wrong API key")
    assert w.dev.driver.callsNamed("runIn").last()[1..2] == [1800, "connectNow"]
    assert w.rat.received.isEmpty()
    w.rat = new FakeRatgdo(d: w.d, psk: KEY.decodeBase64(), wrongKey: true)
    w.dev.connectNow(); w.hub.settle(); w.pump()
    assert w.dev.driver.log.at("error").size() == 1
}

check("a key that doesn't match the device, without the device saying so, is still caught") {
    String other = ("AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyE=")
    World w = world(root, KEY)
    w.rat = new FakeRatgdo(d: w.d, psk: other.decodeBase64(), entities: w.rat.entities)
    w.dev.updated(); w.hub.settle(); w.pump()
    assert w.dev.current.networkStatus == "bad key"
}

check("a ratgdo without encryption is refused, and says to add a key") {
    World w = world(root, KEY)
    w.rat.plaintext = true
    w.dev.updated(); w.hub.settle(); w.pump()
    assert w.dev.current.networkStatus == "bad key" && w.dev.current.lastError.contains("no API key set")
}

check("a malformed API key never opens the socket") {
    World w = world(root, KEY)
    w.dev.driver.settings.apiKey = "my-password"
    w.dev.updated(); w.hub.settle()
    assert !w.dev.driver.callsNamed("socket.connect") && w.dev.current.networkStatus == "bad key"
}

check("no IP or key: offline with a hint, no socket, no watchdog") {
    World w = world(root, KEY)
    w.dev.driver.settings.host = null
    w.dev.updated(); w.hub.settle()
    assert w.dev.current.networkStatus == "offline" && w.dev.current.lastError.contains("IP address")
    assert !w.dev.driver.callsNamed("socket.connect") && !w.dev.driver.callsNamed("runEvery1Minute")
}

check("an unreachable ratgdo backs off 5, 10, 20 ... up to 300 s, then resets once connected") {
    World w = world(root, KEY)
    w.dev.driver.interfaces.rawSocket.refuse = true
    w.dev.updated(); w.hub.settle()
    8.times { w.dev.connectNow(); w.hub.settle() }
    List delays = w.dev.driver.callsNamed("runIn").findAll { it[2] == "connectNow" }.collect { it[1] }
    assert delays == [5, 10, 20, 40, 80, 160, 300, 300, 300]
    assert w.dev.current.networkStatus == "offline" && w.dev.current.lastError.contains("Can't reach")
    w.dev.driver.interfaces.rawSocket.refuse = false
    w.dev.connectNow(); w.hub.settle(); w.pump()
    assert w.dev.current.networkStatus == "online" && w.dev.driver.state.retry == 0
}

check("a handshake that never finishes times out after 15 s") {
    World w = world(root, KEY)
    w.rat.silent = true
    w.dev.updated(); w.hub.settle(); w.pump()
    assert w.dev.driver.callsNamed("runIn").find { it[2] == "handshakeTimeout" }[1] == 15
    w.dev.handshakeTimeout(); w.hub.settle()
    assert w.dev.current.networkStatus == "offline" && w.dev.current.lastError.contains("handshake")
}

check("watchdog: quiet for 50 s sends a ping, 150 s reconnects") {
    World w = connected(root, KEY)
    w.dev.watchdog(); w.pump()
    assert w.sentTypes().last() == 20
    w.hub.advance(55000)
    w.dev.watchdog(); w.pump()
    assert w.sentTypes().last() == 7
    w.hub.advance(100000)
    w.dev.watchdog(); w.hub.settle()
    assert w.dev.current.networkStatus == "offline" && w.dev.current.lastError.contains("No reply")
}

check("a tampered frame drops the connection instead of being trusted") {
    World w = connected(root, KEY)
    byte[] f = w.rat.msg(24, w.d.concat(w.d.pbFixed32(1, LIGHT), w.d.pbVarint(2, 1)))
    f[f.length - 1] = (byte) (f[f.length - 1] ^ 1)
    w.deliver(f); w.hub.settle()
    assert w.dev.current.light == "off" && w.dev.current.networkStatus == "offline"
}

check("a socket error reconnects; commands while offline are dropped with a warning") {
    World w = connected(root, KEY)
    w.dev.socketStatus("receive error: Stream closed"); w.hub.settle()
    assert w.dev.current.networkStatus == "offline"
    int sends = w.dev.driver.callsNamed("socket.send").size()
    w.dev.open(); w.dev.lightOn()
    assert w.dev.driver.callsNamed("socket.send").size() == sends
    assert w.dev.driver.log.at("warn").any { it.contains("not connected") }
}

check("keys and nonces never reach state") {
    World w = connected(root, KEY)
    String s = groovy.json.JsonOutput.toJson(w.dev.driver.state)
    assert !s.contains("tx") && !s.contains("hs") && s.length() < 100
}

check("debug logging turns itself off after 30 minutes") {
    World w = world(root, KEY)
    w.dev.driver.settings.logEnable = true
    w.dev.updated(); w.hub.settle()
    assert w.dev.driver.callsNamed("runIn").any { it[1] == 1800 && it[2] == "logsOff" }
    w.dev.logsOff()
    assert w.dev.driver.settings.logEnable == false
}

check("new driver code (memory cleared, socket maybe still open): the watchdog reconnects within a minute") {
    World w = connected(root, KEY)
    w.d.MEM.clear()
    w.dev.parse("0100"); w.hub.settle()        // data from the orphaned socket is ignored
    w.dev.watchdog(); w.hub.settle(); w.pump()
    assert w.dev.current.networkStatus == "online" && w.d.MEM[w.dev.idAsLong].phase == "ready"
}

check("a late socket error during a new handshake is ignored; the handshake timeout covers it") {
    World w = world(root, KEY)
    w.rat.silent = true
    w.dev.updated(); w.hub.settle(); w.pump()
    w.dev.socketStatus("receive error: Socket closed"); w.hub.settle()
    assert w.dev.current.networkStatus == "connecting" && !w.dev.driver.callsNamed("runIn").any { it[2] == "connectNow" }
}

check("refresh while offline connects straight away") {
    World w = world(root, KEY)
    w.dev.driver.interfaces.rawSocket.refuse = true
    w.dev.updated(); w.hub.settle()
    w.dev.driver.interfaces.rawSocket.refuse = false
    w.dev.refresh(); w.hub.settle(); w.pump()
    assert w.dev.current.networkStatus == "online"
}

check("the port is text (no '6,053' on the settings page); numbers from older saves and commas still work") {
    [["6053", 6053], [6053L, 6053], ["6,053", 6053], [" 7000 ", 7000], [null, 6053]].each { v, want ->
        World w = world(root, KEY)
        w.dev.driver.settings.port = v
        w.dev.updated(); w.hub.settle()
        assert w.dev.driver.callsNamed("socket.connect")[0][2] == want, "port ${v}"
    }
    World w = world(root, KEY)
    w.dev.driver.settings.port = "60a"
    w.dev.updated(); w.hub.settle()
    assert !w.dev.driver.callsNamed("socket.connect") && w.dev.current.lastError.contains("API port")
}

check("ratgdo32 Disco and encoder entities: vehicle presence, arriving/leaving, manually operated; extras ignored") {
    World w = world(root, KEY)
    Class d = w.d
    def ent = { int type, int k, String objId, String name ->
        w.rat.entities[k] = [type, d.concat(d.concat(d.pbString(1, objId), d.pbFixed32(2, k)), d.pbString(3, name))]
    }
    ent(12, 0x2001, "vehicle_detected", "Vehicle detected")
    ent(12, 0x2002, "vehicle_arriving", "Vehicle arriving")
    ent(12, 0x2003, "vehicle_leaving", "Vehicle leaving")
    ent(12, 0x2004, "manually_operated", "Manually Operated")
    ent(16, 0x2005, "vehicle_distance_actual_filtered", "Vehicle distance actual filtered")
    ent(16, 0x2006, "voltage", "Voltage")
    ent(16, 0x2007, "encoder", "Encoder")
    ent(17, 0x2008, "laser", "LASER")
    ent(61, 0x2009, "encoder_calibration_reset", "Encoder Calibration Reset")
    w.dev.updated(); w.hub.settle(); w.pump()
    Map roles = w.d.MEM[w.dev.idAsLong].roles
    assert roles.vehicle == 0x2001 && roles.arriving == 0x2002 && roles.leaving == 0x2003 && roles.manual == 0x2004
    assert roles.openings == OPENINGS && roles.motion == MOTION && roles.size() == 14
    def bin = { int k, int v -> w.push(21, d.concat(d.pbFixed32(1, k), d.pbVarint(2, v))) }
    bin(0x2001, 1); assert w.dev.current.presence == "present"
    bin(0x2002, 1); assert w.dev.current.vehicleMotion == "arriving"
    bin(0x2002, 0); assert w.dev.current.vehicleMotion == "none"
    bin(0x2003, 1); assert w.dev.current.vehicleMotion == "leaving"
    bin(0x2001, 0); bin(0x2003, 0); assert w.dev.current.presence == "not present" && w.dev.current.vehicleMotion == "none"
    bin(0x2004, 1); assert w.dev.current.manuallyOperated == "yes"
}

check("entity names from every supported firmware map to the right role, with no false matches") {
    Class d = new Hub(root).compile(new File(root, "drivers/ratgdo-esphome.groovy"))
    Map want = [
        // ratgdo dry-contact and Security+ 1.0 builds
        "binary_sensor|open_limit_switch open limit switch": null,
        "binary_sensor|close_limit_switch close limit switch": null,
        "binary_sensor|dry_contact_light dry contact light": null,
        "sensor|encoder encoder": null,
        "sensor|wifi_signal wifi signal": null,
        "button|sync sync": null,
        // Gelidus GRGDO with SecplusGDO firmware
        "cover|garage_door garage door": "door",
        "light|garage_door_light garage door light": "light",
        "lock|lock_remotes lock remotes": "remotes",
        "binary_sensor|garage_door_obstruction_sensor garage door obstruction sensor": "obstruction",
        "binary_sensor|garage_motion_sensor garage motion sensor": "motion",
        "binary_sensor|garage_door_motor garage door motor": "motor",
        "binary_sensor|garage_button garage button": "wallButton",
        "binary_sensor|synced synced": null,
        "binary_sensor|vehicle_parked vehicle parked": "vehicle",
        "binary_sensor|car_parked car parked": "vehicle",
        "binary_sensor|vehicle_arriving vehicle arriving": "arriving",
        "sensor|garage_door_openings garage door openings": "openings",
        "sensor|vehicle_distance vehicle distance": null,
        "button|factory_reset factory reset": null,
        "button|re-sync re-sync": null,
        "button|reset_door_timings reset door timings": null,
    ]
    want.each { k, role ->
        List p = k.tokenize("|")
        assert d.entityRole(p[0], p[1]) == role, k
    }
}

check("Gelidus SecplusGDO end to end: its entity list, states, and Toggle without a Toggle button stops a moving door") {
    World w = world(root, KEY)
    Class d = w.d
    w.rat.entities.clear()
    def ent = { int type, int k, String objId, String name ->
        w.rat.entities[k] = [type, d.concat(d.concat(d.pbString(1, objId), d.pbFixed32(2, k)), d.pbString(3, name))]
    }
    ent(12, 0x3001, "synced", "Synced")
    ent(12, 0x3002, "garage_button", "Garage Button")
    ent(12, 0x3003, "garage_door_motor", "Garage Door Motor")
    ent(12, 0x3004, "garage_door_obstruction_sensor", "Garage Door Obstruction Sensor")
    ent(12, 0x3005, "garage_motion_sensor", "Garage Motion Sensor")
    ent(12, 0x3006, "vehicle_parked", "Vehicle parked")
    ent(12, 0x3007, "vehicle_arriving", "Vehicle arriving")
    ent(12, 0x3008, "vehicle_leaving", "Vehicle leaving")
    ent(13, 0x3009, "garage_door", "Garage Door")
    ent(15, 0x300a, "garage_door_light", "Garage Door Light")
    ent(58, 0x300b, "lock_remotes", "Lock remotes")
    ent(16, 0x300c, "garage_door_openings", "Garage Door Openings")
    ent(16, 0x300d, "vehicle_distance", "Vehicle Distance")
    ent(61, 0x300e, "re-sync", "Re-sync")
    ent(61, 0x300f, "factory_reset", "Factory Reset")
    ent(17, 0x3010, "toggle_only", "Toggle Only")
    w.rat.initialStates = [[22, d.pbFixed32(1, 0x3009)], [21, d.concat(d.pbFixed32(1, 0x3006), d.pbVarint(2, 1))],
                           [25, d.concat(d.pbFixed32(1, 0x300c), d.pbFloat(2, 42f))]]
    w.dev.updated(); w.hub.settle(); w.pump()
    assert w.d.MEM[w.dev.idAsLong].roles == [wallButton: 0x3002, motor: 0x3003, obstruction: 0x3004, motion: 0x3005, vehicle: 0x3006,
        arriving: 0x3007, leaving: 0x3008, door: 0x3009, light: 0x300a, remotes: 0x300b, openings: 0x300c]
    assert w.dev.current.subMap(["networkStatus", "door", "presence", "openings"]) ==
        [networkStatus: "online", door: "closed", presence: "present", openings: 42L]
    w.push(22, d.concat(d.concat(d.pbFixed32(1, 0x3009), d.pbFloat(3, 0.3f)), d.pbVarint(5, 1)))
    w.dev.toggle(); w.pump()
    assert w.lastSent(30)[1][8] == 1L, "a moving door stops"
    w.push(22, d.concat(d.pbFixed32(1, 0x3009), d.pbFloat(3, 0.3f)))
    w.dev.toggle(); w.pump()
    assert Float.intBitsToFloat(w.lastSent(30)[1][5]) == 0f, "a stopped, part-open door closes"
    int before = w.rat.received.size()
    w.dev.refresh(); w.pump()
    assert w.rat.received.drop(before).collect { it[0] } == [20], "no Query status button: only re-subscribe"
}

check("two updates in one burst log once (seen on a C-8: 'door is opening' twice, 24 ms apart)") {
    World w = connected(root, KEY)
    Class d = w.d
    byte[] a = w.rat.msg(22, d.concat(d.concat(d.pbFixed32(1, DOOR), d.pbFloat(3, 0.01f)), d.pbVarint(5, 1)))
    byte[] l = w.rat.msg(24, d.concat(d.pbFixed32(1, LIGHT), d.pbVarint(2, 1)))
    byte[] b = w.rat.msg(22, d.concat(d.concat(d.pbFixed32(1, DOOR), d.pbFloat(3, 0.02f)), d.pbVarint(5, 1)))
    w.deliver(d.cat(a, l, b)); w.hub.settle()
    assert w.dev.driver.log.at("info").count { it.contains("door is opening") } == 1
    assert w.dev.events.count { it.name == "door" && it.value == "opening" } == 1
}

check("while the door moves, position is reported every 10%; the stop is exact") {
    World w = connected(root, KEY)
    Class d = w.d
    int before = w.dev.events.count { it.name == "position" }
    (1..28).each { i ->   // a 14 s open at 2 updates a second
        w.push(22, d.concat(d.concat(d.pbFixed32(1, DOOR), d.pbFloat(3, (float) (i / 28))), d.pbVarint(5, i < 28 ? 1 : 0)))
    }
    List pos = w.dev.events.findAll { it.name == "position" }.drop(before)*.value
    assert pos.size() <= 11 && pos.last() == 100L && w.dev.current.door == "open"
    w.push(22, d.concat(d.concat(d.pbFixed32(1, DOOR), d.pbFloat(3, 0.43f)), d.pbVarint(5, 0)))
    assert w.dev.current.position == 43L
}

check("Save and uninstall say goodbye (DisconnectRequest) before closing; errors just close") {
    World w = connected(root, KEY)
    w.dev.updated(); w.hub.settle(); w.pump()
    assert w.rat.received.collect { it[0] }.contains(5)
    assert w.dev.current.networkStatus == "online"
    int n = w.rat.received.size()
    w.dev.uninstalled(); w.hub.settle(); w.pump()
    assert w.rat.received.drop(n).collect { it[0] } == [5]
    World e = connected(root, KEY)
    e.dev.socketStatus("receive error: Stream closed"); e.hub.settle()
    assert !e.rat.received.collect { it[0] }.contains(5)
}

check("another ESPHome device at the ratgdo's address is named, not mistaken for a wrong key; Save re-learns") {
    World w = connected(root, KEY)
    assert w.dev.data.esphomeName == "nexus-gate"
    w.rat = new FakeRatgdo(d: w.d, psk: KEY.decodeBase64(), entities: w.rat.entities, serverName: "bt-proxy-1")
    w.dev.connectNow(); w.hub.settle(); w.pump()
    assert w.dev.current.networkStatus == "offline" && w.dev.current.lastError.contains("'bt-proxy-1'")
    assert w.dev.current.lastError.contains("'nexus-gate'") && w.rat.received.isEmpty(), "nothing sent after the hello"
    w.dev.updated(); w.hub.settle(); w.pump()
    assert w.dev.current.networkStatus == "online" && w.dev.data.esphomeName == "bt-proxy-1"
}

check("a wrong key names the device that rejected it") {
    World w = world(root, KEY)
    w.rat.wrongKey = true
    w.dev.updated(); w.hub.settle(); w.pump()
    assert w.dev.current.lastError == "Wrong API key: 'nexus-gate' at 172.16.214.150 rejected it"
}

check("healthStatus: online when connected, offline when not; a reconnect in progress keeps it") {
    World w = connected(root, KEY)
    assert w.dev.current.healthStatus == "online"
    w.dev.socketStatus("receive error: Stream closed"); w.hub.settle()
    assert w.dev.current.healthStatus == "offline"
    w.rat = new FakeRatgdo(d: w.d, psk: KEY.decodeBase64(), entities: w.rat.entities, silent: true)
    w.dev.connectNow(); w.hub.settle(); w.pump()
    assert w.dev.current.networkStatus == "connecting" && w.dev.current.healthStatus == "offline"
}

check("the wall button: each press is a pushed event, the release is not; push() never moves the door") {
    World w = connected(root, KEY)
    Class d = w.d
    assert w.dev.current.numberOfButtons == 1
    def btn = { int v -> w.push(21, d.concat(d.pbFixed32(1, BTN_SENSOR), d.pbVarint(2, v))) }
    btn(1); btn(0); btn(1); btn(0)
    List p = w.dev.events.findAll { it.name == "pushed" }
    assert p.size() == 2 && p.every { it.value == 1 && it.isStateChange && it.type == "physical" }
    int sent = w.rat.received.size()
    w.dev.push(1); w.pump()
    assert w.dev.events.findAll { it.name == "pushed" }.last().type == "digital" && w.rat.received.size() == sent
}

Check.finish()
