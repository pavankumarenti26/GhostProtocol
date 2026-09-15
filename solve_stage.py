from pathlib import Path
import hashlib
import struct
import sys

from artifact.vm import execute


def parse_artifact(path):
    data = Path(path).read_bytes()

    offset = 0

    if data[offset:offset + 4] != b"GP91":
        raise ValueError("Invalid artifact magic")

    offset += 4

    version = data[offset]
    offset += 1

    program_len = struct.unpack_from("<H", data, offset)[0]
    offset += 2

    program = data[offset:offset + program_len]
    offset += program_len

    public_seed = data[offset:offset + 16]
    offset += 16

    nonce = data[offset:offset + 12]
    offset += 12

    ciphertext_len = struct.unpack_from("<H", data, offset)[0]
    offset += 2

    ciphertext = data[offset:offset + ciphertext_len]

    return version, program, public_seed, nonce, ciphertext


def main():
    if len(sys.argv) != 2:
        print("Usage: python solve_stage.py <artifact>")
        raise SystemExit(1)

    version, program, public_seed, nonce, ciphertext = parse_artifact(
        sys.argv[1]
    )

    registers = execute(program)

    vm_state = bytes(registers) * 4

    stage_value = hashlib.sha256(
        b"GhostProtocol-PublicStage" +
        public_seed +
        vm_state
    ).digest()

    print("=" * 60)
    print("Ghost Protocol Stage Calculator")
    print("=" * 60)

    print(f"Version:     {version}")
    print(f"Program len: {len(program)}")
    print(f"Program:     {program.hex(' ')}")
    print(f"Public seed: {public_seed.hex()}")
    print(f"Nonce:       {nonce.hex()}")
    print(f"Ciphertext:  {len(ciphertext)} bytes")

    print()
    print("VM registers:")

    for i, value in enumerate(registers):
        print(f"R{i} = {value:02x}")

    print()
    print("Stage value:")
    print(stage_value.hex())


if __name__ == "__main__":
    main()
