from pathlib import Path
import hashlib
import struct

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from vm import execute


MAGIC = b"GP91"
VERSION = 2

# VM program:
#
# PUSH 42
# PUSH 21
# ADD
# ROL 2
# HALT

program = bytes([
    0x01, 0x2A,
    0x01, 0x15,
    0x03,
    0x04, 0x02,
    0x05
])

vm_result = execute(program)

# Turn the VM result into deterministic key material.
key = hashlib.sha256(
    b"GP91-key-v1" + bytes([vm_result])
).digest()

secret = b"THE_NEXT_STAGE_IS_WAITING"

aes = AESGCM(key)
nonce = b"GP91NONCE123"

encrypted = aes.encrypt(
    nonce,
    secret,
    MAGIC + bytes([VERSION])
)

data = (
    MAGIC +
    struct.pack("<B", VERSION) +
    struct.pack("<H", len(program)) +
    program +
    nonce +
    struct.pack("<H", len(encrypted)) +
    encrypted
)

output = Path(__file__).parent / "gp-core-0917.bin"
output.write_bytes(data)

print(f"Generated {output}")
print(f"VM result: {vm_result}")
print(f"Encrypted payload: {len(encrypted)} bytes")