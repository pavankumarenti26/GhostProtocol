import requests

BASE = "http://localhost:5000"


def get_challenge():
    r = requests.get(f"{BASE}/api/sync", timeout=10)
    r.raise_for_status()
    return r.json()


def oracle(iv, ciphertext):
    r = requests.post(
        f"{BASE}/api/sync/check",
        json={
            "iv": iv.hex(),
            "ciphertext": ciphertext.hex(),
        },
        timeout=10,
    )
    r.raise_for_status()
    return bool(r.json().get("valid", False))


def recover_block(previous, current):
    intermediate = [0] * 16
    plaintext = [0] * 16

    forged = bytearray(previous)

    for pos in range(15, -1, -1):
        pad = 16 - pos

        # Force bytes already recovered to the current padding value.
        for j in range(pos + 1, 16):
            forged[j] = intermediate[j] ^ pad

        found = None

        for guess in range(256):
            forged[pos] = guess

            if oracle(bytes(forged), current):
                found = guess
                break

        if found is None:
            raise RuntimeError(
                f"No valid candidate at position {pos}"
            )

        intermediate[pos] = found ^ pad
        plaintext[pos] = intermediate[pos] ^ previous[pos]

        value = plaintext[pos]

        if 32 <= value <= 126:
            display = chr(value)
        else:
            display = "."

        print(
            f"    pos={pos:02d} "
            f"intermediate={intermediate[pos]:02x} "
            f"plaintext={value:02x} "
            f"({display})"
        )

    return bytes(plaintext)


def main():
    print("=" * 60)
    print("Ghost Protocol CBC Padding Oracle")
    print("=" * 60)
    print()

    challenge = get_challenge()

    iv = bytes.fromhex(challenge["iv"])
    ciphertext = bytes.fromhex(challenge["ciphertext"])

    if len(iv) != 16:
        raise RuntimeError("Invalid IV length")

    if not ciphertext or len(ciphertext) % 16:
        raise RuntimeError("Invalid ciphertext length")

    blocks = [
        ciphertext[i:i + 16]
        for i in range(0, len(ciphertext), 16)
    ]

    print(f"Blocks: {len(blocks)}")
    print()

    recovered = b""
    previous = iv

    for index, current in enumerate(blocks):
        print(f"[*] Recovering block {index + 1}/{len(blocks)}")

        block = recover_block(previous, current)

        print()
        print(f"    Plaintext: {block!r}")
        print()

        recovered += block
        previous = current

    # Remove PKCS#7 padding.
    pad = recovered[-1]

    if pad < 1 or pad > 16:
        raise RuntimeError(
            f"Invalid PKCS#7 padding byte: {pad:#x}"
        )

    if recovered[-pad:] != bytes([pad]) * pad:
        raise RuntimeError("Invalid PKCS#7 padding")

    recovered = recovered[:-pad]

    print("=" * 60)
    print("Recovered plaintext:")
    print(repr(recovered))
    print("=" * 60)
    print()

    prefix = b"GP-SYNC-V3|"

    if not recovered.startswith(prefix):
        raise RuntimeError(
            f"Unexpected plaintext: {recovered!r}"
        )

    shard = recovered[len(prefix):]

    if len(shard) != 16:
        raise RuntimeError(
            f"Expected 16-byte shard, got {len(shard)} bytes"
        )

    print(f"Recovered shard: {shard.hex()}")
    print()


if __name__ == "__main__":
    main()
