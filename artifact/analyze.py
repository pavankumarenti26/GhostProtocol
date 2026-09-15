from pathlib import Path
import struct
from vm import execute

data = Path(__file__).with_name("gp-core-0917.bin").read_bytes()

offset = 0

magic = data[offset:offset + 4]
offset += 4

version = data[offset]
offset += 1

program_len = struct.unpack_from("<H", data, offset)[0]
offset += 2

program = data[offset:offset + program_len]
offset += program_len

payload_len = struct.unpack_from("<H", data, offset)[0]
offset += 2

payload = data[offset:offset + payload_len]

print("Magic:", magic)
print("Version:", version)
print("Program:", program.hex(" "))
print("VM result:", execute(program))
print("Payload:", payload)