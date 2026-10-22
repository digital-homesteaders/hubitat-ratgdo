/**
 * Compile every driver against the hub stubs and run its top-level code
 * (definition, metadata, preferences), then check for things Hubitat's
 * Groovy 2.4 sandbox refuses or garbles.
 */

import static Check.check

File root = new File(getClass().protectionDomain.codeSource.location.path).parentFile.parentFile
Hub hub = new Hub(root)
List<File> files = new File(root, "drivers").listFiles().findAll { it.name.endsWith(".groovy") }.sort { it.path }

files.each { File f ->
    check("compiles and loads: drivers/${f.name}") {
        HubitatScript s = hub.instance(f)
        assert s.callsNamed("definition"), "no definition(...)"
        assert s.callsNamed("definition")[0][1].singleThreaded == true, "parse, commands and timers must not interleave"
    }
}

List<String> dslWords = ["definition", "capability", "attribute", "command", "fingerprint", "input", "section"]
files.each { File f ->
    check("no method shadows a definition word: ${f.name}") {
        List<String> clash = hub.compile(f).declaredMethods*.name.unique().findAll { it in dslWords }
        assert !clash
    }
}

// Groovy 2.5+ methods that compile here only because the JDK or a newer Groovy has them.
files.each { File f ->
    check("no post-2.4 Groovy methods: ${f.name}") {
        List bad = ["takeRight(", "dropRight(", ".tap {", "?.with(true)", "=> "].findAll { f.text.contains(it) }
        assert !bad
    }
}

// Classes and calls the sandbox may refuse; the driver uses plain loops instead.
files.each { File f ->
    check("no sandbox-risky calls: ${f.name}") {
        List bad = ["System.", ".clone()", "Thread.", "getClass()", "Arrays.", "Class.forName", "@CompileStatic", "synchronized"]
            .findAll { f.text.contains(it) }
        assert !bad
    }
}

// Pasting into Hubitat's editor can garble non-ASCII text.
files.each { File f ->
    check("ASCII only: ${f.name}") {
        List bad = f.readLines("UTF-8").withIndex().findAll { line, i -> line.any { (it as char) > 127 } }.collect { it[1] + 1 }
        assert !bad, "non-ASCII on lines ${bad}"
    }
}

// Hubitat refuses reflection-like property names even on Maps.
files.each { File f ->
    check("no sandbox-blocked property names: ${f.name}") {
        def m = f.text =~ /(?m)^(?!\s*(\/\/|\*)).*?(\.(fields|properties|methods|declaredFields|declaredMethods|metaClass)\b|\[\s*"(fields|properties|methods|class|metaClass)"\s*\])/
        assert !m.find(), "found: ${m.group(0)?.trim()}"
    }
}

check("every driver carries the same version") {
    Set versions = files.collect { f -> (f.text =~ /static final String DRIVER_VERSION = "([^"]+)"/).with { it.find() ? it.group(1) : "none" } } as Set
    assert versions.size() == 1 && !("none" in versions), "versions: ${versions}"
}

check("the API key is a password input and is never logged") {
    String t = new File(root, "drivers/ratgdo-esphome.groovy").text
    assert t =~ /input "apiKey", "password"/
    assert !(t =~ /log\.\w+[^\n]*apiKey/) && !(t =~ /log\.\w+[^\n]*psk/)
}

Check.finish()
