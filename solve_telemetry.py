import json
import sys


def xor_bytes(a, b):
    return bytes(
        x ^ y
        for x, y in zip(a, b)
    )


def recover_plaintext(known_plaintext, known_ciphertext, target_ciphertext):
    # AES-GCM ciphertext consists of:
    #
    #     encrypted_data || 16-byte authentication tag
    #
    # We only need the encrypted_data portion.
    known_ciphertext = known_ciphertext[:-16]
    target_ciphertext = target_ciphertext[:-16]

    # Recover the GCM keystream from:
    #
    #     plaintext XOR ciphertext
    #
    keystream = xor_bytes(
        known_plaintext,
        known_ciphertext
    )

    # Reuse that keystream against the second ciphertext.
    return xor_bytes(
        target_ciphertext,
        keystream
    )


def main():
    if len(sys.argv) != 2:
        print(
            "Usage: python solve_telemetry.py telemetry.json"
        )
        raise SystemExit(1)

    path = sys.argv[1]

    with open(path, "r") as f:
        data = json.load(f)

    known_plaintext = (
        b"GP-TELEMETRY-V1:"
        b"STATUS=OPERATIONAL;"
        b"NODE=GHOST-"
    )

    known_ciphertext = bytes.fromhex(
        data["known"]
    )

    protected_ciphertext = bytes.fromhex(
        data["protected"]
    )

    recovered = recover_plaintext(
        known_plaintext,
        known_ciphertext,
        protected_ciphertext
    )

    print("=" * 60)
    print("Ghost Protocol Telemetry Solver")
    print("=" * 60)

    print()
    print("Nonce:")
    print(data["nonce"])

    print()
    print("Recovered plaintext:")
    print(recovered)

    print()

    if recovered.startswith(
        b"GP-TELEMETRY-V1:"
    ):
        print("[+] NONCE REUSE EXPLOITED")
    else:
        print("[-] Recovery failed")


if __name__ == "__main__":
    main()
