package hubitat.helper

/** Stand-in for Hubitat's hubitat.helper.HexUtils (upper-case hex, as the hub sends). */
class HexUtils {
    static byte[] hexStringToByteArray(String s) { s.decodeHex() }
    static String byteArrayToHexString(byte[] b) { b.encodeHex().toString().toUpperCase() }
}
