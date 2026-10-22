"""Reference Noise_NNpsk0 transcript for the ESPHome API, made with the same
`noise` library aioesphomeapi uses. Fixed keys so the Groovy port can be
checked byte for byte."""
import base64, json, sys
from noise.connection import NoiseConnection, Keypair

NAME = b"Noise_NNpsk0_25519_ChaChaPoly_SHA256"
PROLOGUE = b"NoiseAPIInit\x00\x00"
psk = bytes(range(1, 33))
ie = bytes.fromhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
re_ = bytes.fromhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")

def mk(initiator, eph):
    c = NoiseConnection.from_name(NAME)
    c.set_as_initiator() if initiator else c.set_as_responder()
    c.set_psks(psk)
    c.set_prologue(PROLOGUE)
    c.set_keypair_from_private_bytes(Keypair.EPHEMERAL, eph)
    c.start_handshake()
    return c

i, r = mk(True, ie), mk(False, re_)
m1 = i.write_message(); r.read_message(m1)
m2 = r.write_message(); i.read_message(m2)
assert i.handshake_finished and r.handshake_finished

def pkt(t, data):
    return bytes(((t >> 8) & 255, t & 255, (len(data) >> 8) & 255, len(data) & 255)) + data

# HelloRequest: client_info "Hubitat ratgdo", api 1.10
hello = b"\x0a\x0eHubitat ratgdo" + b"\x10\x01" + b"\x18\x0a"
c2s = [pkt(1, hello), pkt(3, b"")]
# HelloResponse: api 1.19, server_info "2026.10.0", name "nexus-gate"
hr = b"\x08\x01\x10\x13" + b"\x1a\x092026.10.0" + b"\x22\x0anexus-gate"
s2c = [pkt(2, hr), pkt(7, b"")]
out = {
    "psk": base64.b64encode(psk).decode(),
    "initiatorEphemeral": ie.hex(), "responderEphemeral": re_.hex(),
    "msg1": m1.hex(), "msg2": m2.hex(),
    "clientPlain": [p.hex() for p in c2s], "clientCipher": [i.encrypt(p).hex() for p in c2s],
    "serverPlain": [p.hex() for p in s2c], "serverCipher": [r.encrypt(p).hex() for p in s2c],
}
json.dump(out, sys.stdout, indent=2)
print()
