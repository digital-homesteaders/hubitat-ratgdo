/**
 * The driver's hand-written crypto against published vectors (RFC 7748
 * X25519, RFC 8439 ChaCha20 and Poly1305), then a full
 * Noise_NNpsk0_25519_ChaChaPoly_SHA256 handshake and transport frames made by
 * the Python `noise` library that aioesphomeapi (Home Assistant) uses
 * (tests/fixtures/noise_vectors.py), byte for byte.
 */

import groovy.json.JsonSlurper
import static Check.check

File root = new File(getClass().protectionDomain.codeSource.location.path).parentFile.parentFile
Class d = new Hub(root).compile(new File(root, "drivers/ratgdo-esphome.groovy"))
Map v = new JsonSlurper().parse(new File(root, "tests/fixtures/noise-vectors.json")) as Map

byte[] h(String s) { s.decodeHex() }
String hx(byte[] b) { b.encodeHex().toString() }

check("X25519: RFC 7748 section 5.2 vector") {
    assert hx(d.x25519(h("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"),
                       h("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c"))) ==
        "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"
}

check("X25519: RFC 7748 section 6.1 public keys and shared secret") {
    byte[] a = h("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
    byte[] b = h("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
    byte[] aPub = d.x25519(a, d.basePoint()), bPub = d.x25519(b, d.basePoint())
    assert hx(aPub) == "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
    assert hx(bPub) == "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
    assert hx(d.x25519(a, bPub)) == "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
    assert hx(d.x25519(b, aPub)) == hx(d.x25519(a, bPub))
}

check("ChaCha20 block: RFC 8439 section 2.3.2") {
    byte[] key = (0..31).collect { it as byte } as byte[]
    assert hx(d.chachaBlock(key, 1, h("000000090000004a00000000"))) ==
        "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e" +
        "d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e"
}

check("Poly1305: RFC 8439 section 2.5.2") {
    assert hx(d.poly1305(h("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b"),
                         "Cryptographic Forum Research Group".getBytes("US-ASCII"))) == "a8061dc1305136c6c22b8baf0c0127a9"
}

check("AEAD: seal and open round trip; any flipped bit is refused") {
    byte[] key = new byte[32]; key[3] = 7
    byte[] msg = (0..200).collect { (it * 7) as byte } as byte[]
    byte[] sealed = d.aeadSeal(key, 5L, "ad".bytes, msg)
    assert sealed.length == msg.length + 16
    assert d.aeadOpen(key, 5L, "ad".bytes, sealed) == msg
    assert d.aeadOpen(key, 6L, "ad".bytes, sealed) == null
    assert d.aeadOpen(key, 5L, "xx".bytes, sealed) == null
    [0, 100, sealed.length - 1].each { i ->
        byte[] bad = sealed.clone(); bad[i] = (byte) (bad[i] ^ 1)
        assert d.aeadOpen(key, 5L, "ad".bytes, bad) == null
    }
}

check("Noise message 1 matches the Python reference byte for byte") {
    Map hs = d.noiseStart(v.psk.decodeBase64(), h(v.initiatorEphemeral))
    assert hx(hs.msg1) == v.msg1
}

check("Noise message 2 verifies, and the session keys match the reference frames in both directions") {
    Map hs = d.noiseStart(v.psk.decodeBase64(), h(v.initiatorEphemeral))
    List keys = d.noiseFinish(hs, h(v.msg2))
    assert keys != null
    v.clientPlain.eachWithIndex { p, i -> assert hx(d.aeadSeal(keys[0], i as long, new byte[0], h(p))) == v.clientCipher[i] }
    v.serverCipher.eachWithIndex { c, i -> assert hx(d.aeadOpen(keys[1], i as long, new byte[0], h(c))) == v.serverPlain[i] }
}

check("Noise message 2 under a different key is refused") {
    byte[] other = v.psk.decodeBase64(); other[0] = (byte) (other[0] ^ 1)
    Map hs = d.noiseStart(other, h(v.initiatorEphemeral))
    assert d.noiseFinish(hs, h(v.msg2)) == null
    assert d.noiseFinish(d.noiseStart(v.psk.decodeBase64(), h(v.initiatorEphemeral)), d.slice(h(v.msg2), 0, 40)) == null
}

check("protobuf: the reference HelloRequest encodes the same; fields decode") {
    byte[] body = d.concat(d.concat(d.pbString(1, "Hubitat ratgdo"), d.pbVarint(2, 1)), d.pbVarint(3, 10))
    assert hx(body) == v.clientPlain[0].substring(8)
    Map f = d.pbDecode(d.concat(d.concat(d.pbFixed32(1, 0xdeadbeef as int), d.pbFloat(3, 0.25f)), d.pbVarint(5, 300)))
    assert f[1] == (0xdeadbeef as int) && Float.intBitsToFloat(f[3]) == 0.25f && f[5] == 300L
    assert new String(d.pbDecode(h(v.serverPlain[0].substring(8)))[4] as byte[], "UTF-8") == "nexus-gate"
}

check("API key: 32 bytes of base64 only") {
    assert d.decodeKey(" ${v.psk} ".toString()).length == 32
    assert d.decodeKey("abc") == null && d.decodeKey("") == null && d.decodeKey(null) == null
    assert d.decodeKey("not base64 at all!!!!!!!!!!!!!!!!!!!!!!!!!!!") == null
}

check("X25519 is quick enough for a C-7 (one handshake under 250 ms here)") {
    byte[] k = new byte[32]; k[0] = 1
    3.times { d.x25519(k, d.basePoint()) }   // warm up
    long t = System.nanoTime()
    Map hs = d.noiseStart(v.psk.decodeBase64(), h(v.initiatorEphemeral))
    d.noiseFinish(hs, h(v.msg2))
    assert (System.nanoTime() - t) / 1e6 < 250
}

Check.finish()
