/**
 * A tiny stand-in for the Hubitat runtime, enough to compile the driver and
 * run it against a fake ratgdo without a hub.
 *
 * Each driver file is compiled as a script whose base class is HubitatScript,
 * which supplies definition/metadata/preferences, state, settings, log,
 * sendEvent, child devices, scheduling and the raw socket. Platform calls that
 * only have side effects (runIn, unschedule, socket sends...) are recorded in
 * `calls` for tests to inspect.
 */

import groovy.json.JsonOutput
import groovy.json.JsonSlurper
import org.codehaus.groovy.control.CompilerConfiguration
import java.lang.reflect.Modifier

class Hub {
    File root
    Map<String, File> driverFiles = [:]   // driver name -> source file
    Map<String, Class> classes = [:]      // path -> compiled class
    long clockOffset = 0                  // added to now(); see advance()
    long nextId = 100
    List<HubitatScript> scripts = []
    GroovyShell shell

    Hub(File root) {
        this.root = root
        CompilerConfiguration cc = new CompilerConfiguration()
        cc.scriptBaseClass = HubitatScript.name
        shell = new GroovyShell(Hub.classLoader, new Binding(), cc)
        // Our drivers, plus stand-ins for the hub's built-in ones.
        (new File(root, "drivers").listFiles() + new File(root, "tests/support/builtin").listFiles())
            .findAll { it.name.endsWith(".groovy") }.each { f ->
                def m = f.text =~ /definition\s*\(\s*name:\s*"([^"]+)"/
                if (m.find()) driverFiles[m.group(1)] = f
            }
    }

    /** Compile a source file (throws on compile errors). */
    Class compile(File f) {
        String key = f.canonicalPath
        if (!classes[key]) classes[key] = shell.parseClass(new GroovyCodeSource(f.text, f.name.replaceAll(/\W/, "_"), "/groovy/script"))
        return classes[key]
    }

    /** A new instance of a driver, with its top-level code run. */
    HubitatScript instance(File f) {
        HubitatScript s = (HubitatScript) compile(f).newInstance()
        s.binding = new Binding()
        s.hub = this
        s.run()
        scripts << s
        return s
    }

    /** Move the hub's clock forward. */
    void advance(long ms) { clockOffset += ms }

    /** End of an execution: every script's state goes through JSON, as on the hub. */
    void settle() {
        scripts.each { it.persistState(); it.device?.commit() }
    }

    /** A device running the named driver. */
    FakeDevice device(String driverName, String dni, Map props = [:], def parent = null) {
        File f = driverFiles[driverName]
        if (!f) throw new IllegalArgumentException("no driver named ${driverName}")
        HubitatScript s = instance(f)
        FakeDevice d = new FakeDevice(id: nextId++, deviceNetworkId: dni, name: props.name ?: driverName,
            label: props.label, driverName: driverName, driver: s)
        s.device = d
        s.parent = parent == null ? null : new Ref(target: parent)
        // Settings start at their declared defaults.
        s.declaredInputs.each { k, v -> if (v != null) s.settings[k] = v }
        return d
    }
}

/** Methods every script gets. */
abstract class HubitatScript extends Script {
    Hub hub
    Map state = [:]
    Map settings = [:]
    Map<String, Object> declaredInputs = [:]
    FakeLog log = new FakeLog()
    FakeDevice device
    Ref parent
    List<FakeDevice> children = []
    List<List> calls = []   // [name, args...]
    FakeInterfaces ifaces

    // Script.setProperty writes to the binding; set real properties instead.
    void setProperty(String name, Object v) {
        if (metaClass.hasProperty(this, name)) metaClass.setProperty(this, name, v)
        else super.setProperty(name, v)
    }

    // Settings are readable as bare names when declared with input.
    def propertyMissing(String name) {
        if (declaredInputs.containsKey(name) || settings.containsKey(name)) return settings[name]
        throw new MissingPropertyException(name, this.class)
    }

    /** Hubitat keeps state as JSON between executions; tests call this to mimic that. */
    void persistState() {
        state = (Map) new JsonSlurper().parseText(JsonOutput.toJson(state))
    }

    // ---- definitions
    void definition(Map m) { calls << ["definition", m] }
    void definition(Map m, Closure c) { calls << ["definition", m]; swallow(c) }
    void metadata(Closure c) { swallow(c) }
    void preferences(Closure c) { swallow(c) }
    private void swallow(Closure c) {
        c.delegate = new Swallow(script: this)
        c.resolveStrategy = Closure.DELEGATE_FIRST
        c.call()
    }

    // ---- time and scheduling
    long now() { System.currentTimeMillis() + (hub?.clockOffset ?: 0) }
    void runIn(Number secs, String handler, Map opts = [:]) { calls << ["runIn", secs, handler, opts] }
    void runEvery1Minute(String handler) { calls << ["runEvery1Minute", handler] }
    void unschedule(String handler = null) { calls << ["unschedule", handler] }

    // ---- raw socket (drivers)
    FakeInterfaces getInterfaces() {
        if (ifaces == null) ifaces = new FakeInterfaces(rawSocket: new FakeRawSocket(calls: calls))
        return ifaces
    }

    // ---- events
    void sendEvent(Map e) { device.applyEvent(e) }

    // ---- child devices
    FakeDevice getChildDevice(String dni) { children.find { it.deviceNetworkId == dni } }
    List<FakeDevice> getChildDevices() { new ArrayList(children) }
    FakeDevice addChildDevice(String namespace, String driverName, String dni, Map props = [:]) {
        if (getChildDevice(dni)) throw new IllegalArgumentException("duplicate dni ${dni}")
        FakeDevice d = hub.device(driverName, dni, props, this)
        children << d
        calls << ["addChildDevice", namespace, driverName, dni, props]
        return d
    }
    void deleteChildDevice(String dni) {
        children.removeAll { it.deviceNetworkId == dni }
        calls << ["deleteChildDevice", dni]
    }

    /** Calls made so far with this name. */
    List callsNamed(String name) { calls.findAll { it[0] == name } }
}

/** Delegate for definition/preferences blocks: inputs are recorded, anything else ignored. */
class Swallow {
    HubitatScript script
    def input(Map m, String name, String type) { record(name, m.defaultValue) }
    def input(String name, String type) { record(name, null) }
    def input(Map m) { record(m.name, m.defaultValue) }
    private void record(def name, def dflt) { script.declaredInputs[name as String] = dflt }
    def methodMissing(String name, def args) {
        args.each { if (it instanceof Closure) { it.delegate = this; it.resolveStrategy = Closure.DELEGATE_FIRST; it.call() } }
        return null
    }
}

class FakeInterfaces {
    FakeRawSocket rawSocket
}

/** interfaces.rawSocket: connect(Map, ip, port), sendMessage(hex), close(). */
class FakeRawSocket {
    List calls
    boolean refuse                 // connect() throws, like an unreachable host
    boolean open
    List<String> sent = []         // hex strings, newest last
    void connect(Map opts, String ip, int port) {
        calls << ["socket.connect", ip, port, opts]
        if (refuse) throw new IOException("No route to host")
        open = true
    }
    void sendMessage(String hex) { sent << hex; calls << ["socket.send", hex] }
    void close() { open = false; calls << ["socket.close"] }
}

class FakeLog {
    List<List<String>> lines = []
    void debug(def m) { lines << ["debug", m.toString()] }
    void info(def m) { lines << ["info", m.toString()] }
    void warn(def m) { lines << ["warn", m.toString()] }
    void error(def m) { lines << ["error", m.toString()] }
    List<String> at(String level) { lines.findAll { it[0] == level }.collect { it[1] } }
}

/** Calls into another script, allowing only its public methods, as Hubitat does. */
class Ref {
    def target
    def methodMissing(String name, def args) {
        Object[] a = args as Object[]
        if (!target.class.methods.any { it.name == name && !Modifier.isPrivate(it.modifiers) }) {
            throw new MissingMethodException(name, target.class, a)
        }
        return target.invokeMethod(name, a)
    }
}

/** A device: data values, current attribute values, events, settings and its driver. */
class FakeDevice {
    long id
    String deviceNetworkId
    String name
    String label
    String driverName
    HubitatScript driver
    Map<String, String> data = [:]
    Map<String, Object> current = [:]
    List<Map> events = []
    List<Map> pending = []   // like Hubitat, currentValue sees an event only after the execution ends (Hub.settle)

    long getIdAsLong() { id }
    String getDisplayName() { label ?: name }
    String getDataValue(String k) { data[k] }
    void updateDataValue(String k, def v) { data[k] = v?.toString() }
    void removeDataValue(String k) { data.remove(k) }
    def currentValue(String attr, boolean skipCache = false) { current[attr] }
    void updateSetting(String k, Map v) { driver.settings[k] = v.type == "bool" ? v.value == "true" : v.value }

    void applyEvent(Map e) {
        // The hub itself drops an event whose value matches the committed one.
        if (!e.isStateChange && current.containsKey(e.name as String) && current[e.name as String]?.toString() == e.value?.toString()) return
        events << new LinkedHashMap(e)
        pending << e
    }

    void commit() {
        pending.each { current[it.name as String] = it.value }
        pending.clear()
    }

    /** The latest event for an attribute. */
    Map lastEvent(String attr) { events.reverse().find { it.name == attr } }

    // Device methods are the driver's public methods.
    def methodMissing(String name, def args) {
        return new Ref(target: driver).methodMissing(name, args)
    }
}
