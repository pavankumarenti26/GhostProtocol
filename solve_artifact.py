from pathlib import Path
import struct
import sys

from artifact.vm import execute


def parse_artifact(path):
    data = Path(path).read_bytes()

    offset = 0

    # ----------------------------------------------
    # Header
    # ----------------------------------------------

    magic = data[offset:offset + 4]
    offset += 4

    if magic != b"GP91":
        raise ValueError("Invalid artifact magic")

    version = data[offset]
    offset += 1

    # ----------------------------------------------
    # VM program
    # ----------------------------------------------

    program_len = struct.unpack_from(
        "<H",
        data,
        offset
    )[0]
    offset += 2

    program = data[
        offset:offset + program_len
    ]
    offset += program_len

    # ----------------------------------------------
    # Public seed
    # ----------------------------------------------

    public_seed = data[
        offset:offset + 16
    ]
    offset += 16

    # ----------------------------------------------
    # AES-GCM nonce
    # ----------------------------------------------

    nonce = data[
        offset:offset + 12
    ]
    offset += 12

    # ----------------------------------------------
    # Ciphertext
    # ----------------------------------------------

    ciphertext_len = struct.unpack_from(
        "<H",
        data,
        offset
    )[0]
    offset += 2

    ciphertext = data[
        offset:offset + ciphertext_len
    ]

    return {
        "version": version,
        "program": program,
        "public_seed": public_seed,
        "nonce": nonce,
        "ciphertext": ciphertext,
    }


def main():
    if len(sys.argv) != 2:
        print(
            "Usage: python solve_artifact.py <artifact>"
        )
        raise SystemExit(1)

    artifact_path = sys.argv[1]

    artifact = parse_artifact(artifact_path)

    print("=" * 60)
    print("Ghost Protocol Artifact Analyzer")
    print("=" * 60)

    print(
        f"Version:     {artifact['version']}"
    )

    print(
        f"Program len: {len(artifact['program'])}"
    )

    print(
        f"Program:     "
        f"{artifact['program'].hex(' ')}"
    )

    print(
        f"Public seed: "
        f"{artifact['public_seed'].hex()}"
    )

    print(
        f"Nonce:       "
        f"{artifact['nonce'].hex()}"
    )

    print(
        f"Ciphertext:  "
        f"{len(artifact['ciphertext'])} bytes"
    )

    # ----------------------------------------------
    # Execute the public VM
    # ----------------------------------------------

    registers = execute(
        artifact["program"]
    )

    print()
    print("VM registers:")

    for index, value in enumerate(registers):
        print(
            f"R{index} = {value:02x}"
        )


if __name__ == "__main__":
    main()
