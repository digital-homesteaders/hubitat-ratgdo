/**
 * Check packageManifest.json against the code, so an HPM install or update
 * gets every file at one version: each driver is listed once, its name and
 * namespace match the code's definition, its importUrl is the manifest
 * location, and the manifest version is the version stamped in every file
 * (scripts/release.sh sets them all).
 */

import groovy.json.JsonSlurper
import static Check.check

File root = new File(getClass().protectionDomain.codeSource.location.path).parentFile.parentFile
Map m = new JsonSlurper().parse(new File(root, "packageManifest.json")) as Map
List<Map> entries = (m.drivers ?: []) as List<Map>
List<File> files = new File(root, "drivers").listFiles().findAll { it.name.endsWith(".groovy") }.sort { it.path }
String base = "https://raw.githubusercontent.com/digital-homesteaders/hubitat-ratgdo/main/"

check("the manifest has a release version") {
    assert m.version ==~ /\d+\.\d+\.\d+/ && m.dateReleased ==~ /\d{4}-\d{2}-\d{2}/ && m.packageName == "ratgdo (ESPHome)"
    assert !m.apps
}

check("every file is stamped with the manifest version") {
    Map stamped = files.collectEntries { f ->
        def v = (f.text =~ /static final String DRIVER_VERSION = "([^"]+)"/)
        [(f.name): v.find() ? v.group(1) : "none"]
    }
    assert stamped.values().every { it == m.version }, "run scripts/release.sh: ${stamped} vs ${m.version}"
}

check("every driver is in the manifest once, required, and nothing else is") {
    assert entries.collect { (it.location as String) - base }.sort() == files.collect { "drivers/" + it.name }.sort()
    assert entries.every { it.required == true && (it.location as String).startsWith(base) }
}

check("manifest names and namespaces match each file's definition, and importUrl is its location") {
    files.each { File f ->
        Map e = entries.find { (it.location as String).endsWith("/drivers/" + f.name) }
        String t = f.text
        String name = (t =~ /definition\(name:\s*"([^"]+)"/).with { it.find() ? it.group(1) : null }
        String ns = (t =~ /namespace:\s*"([^"]+)"/).with { it.find() ? it.group(1) : null }
        String imp = (t =~ /importUrl:\s*"([^"]*)"/).with { it.find() ? it.group(1) : null }
        String constant = (t =~ /static final String DRIVER_NAME = "([^"]+)"/).with { it.find() ? it.group(1) : null }
        assert e.name == name && e.namespace == ns && constant == name, f.name
        assert imp == e.location, "${f.name}: importUrl ${imp} vs manifest ${e.location}"
    }
}

check("manifest ids are unique UUIDs and the licence exists") {
    List ids = entries*.id
    assert ids.every { it ==~ /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/ } && ids.unique(false).size() == ids.size()
    assert new File(root, (m.licenseFile as String) - base).exists()
}

check("the upstream MIT notice ships: LICENSE points at NOTICE, which carries the permission text") {
    String notice = new File(root, "NOTICE").text
    assert new File(root, "LICENSE").text.contains("https://github.com/digital-homesteaders/hubitat-ratgdo/blob/main/NOTICE")
    assert notice.contains("Otto Winter") && notice.contains("Permission is hereby granted")
    files.each { assert it.text.contains("blob/main/NOTICE"), it.name }
}

Check.finish()
