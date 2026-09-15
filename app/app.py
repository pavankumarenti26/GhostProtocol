import os
import hashlib
import secrets
from flask import Flask, request, jsonify, send_from_directory
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

app = Flask(__name__)

INSTANCE_SECRET_PATH = os.environ.get(
    "INSTANCE_SECRET",
    "/app/instance/secret.bin"
)

PUBLIC_SEED = bytes.fromhex(
    os.environ.get("PUBLIC_SEED", "00" * 16)
)

VM_STATE = bytes.fromhex(
    os.environ.get("VM_STATE", "00" * 32)
)

# ---------------------------------------------------------
# Demo/cloud fallback secret
# ---------------------------------------------------------
# In the real competition deployment, provide a unique
# secret file for every team.
if os.path.exists(INSTANCE_SECRET_PATH):
    with open(INSTANCE_SECRET_PATH, "rb") as f:
        INSTANCE_SECRET = f.read()
else:
    INSTANCE_SECRET = secrets.token_bytes(32)

# ---------------------------------------------------------
# Helpers
# ---------------------------------------------------------

def sha256(data):
    return hashlib.sha256(data).digest()


def pkcs7_unpad(data):
    if not data:
        raise ValueError("empty data")

    pad = data[-1]

    if pad < 1 or pad > 16:
        raise ValueError("bad padding")

    if data[-pad:] != bytes([pad]) * pad:
        raise ValueError("bad padding")

    return data[:-pad]


def aes_cbc_decrypt(iv, ciphertext, key):
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )

    decryptor = cipher.decryptor()

    return decryptor.update(ciphertext) + decryptor.finalize()


# ---------------------------------------------------------
# Routes
# ---------------------------------------------------------

@app.route("/")
def index():
    return jsonify({
        "service": "Ghost Protocol",
        "status": "operational",
        "message": "Something is hiding inside the protocol."
    })


@app.route("/api/status")
def status():
    return jsonify({
        "service": "document-service",
        "status": "operational"
    })


@app.route("/api/artifact")
def artifact():
    artifact_id = request.args.get("id")

    if artifact_id != "gp-core-0917":
        return jsonify({
            "error": "artifact not found"
        }), 404

    return jsonify({
        "id": "gp-core-0917",
        "location": "/artifacts/gp-core-0917.bin"
    })


@app.route("/artifacts/<path:filename>")
def artifacts(filename):
    return send_from_directory(
        "/app/artifact",
        filename
    )


@app.route("/api/stage")
def stage():
    value = request.args.get("value", "")

    expected = sha256(
        b"GhostProtocol-PublicStage" +
        PUBLIC_SEED +
        VM_STATE
    ).hex()

    if value.lower() != expected:
        return jsonify({
            "status": "rejected"
        }), 403

    return jsonify({
        "status": "accepted",
        "next": "/api/telemetry"
    })


@app.route("/api/telemetry")
def telemetry():
    # Deliberate nonce reuse for the CTF crypto stage.

    key = sha256(
        b"GhostProtocol-Telemetry" +
        INSTANCE_SECRET
    )

    nonce = b"GhostTelemetryNonce"

    known_plaintext = (
        b"GP-TELEMETRY-V1:STAGE=PUBLIC;TOKEN="
        + b"A" * 10
    )

    protected_plaintext = (
        b"GP-TELEMETRY-V1:STAGE=PRIVATE;TOKEN="
        + INSTANCE_SECRET[:10]
    )

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    aes = AESGCM(key)

    known = aes.encrypt(
        nonce,
        known_plaintext,
        None
    )

    protected = aes.encrypt(
        nonce,
        protected_plaintext,
        None
    )

    return jsonify({
        "algorithm": "AES-GCM",
        "known": known.hex(),
        "protected": protected.hex(),
        "nonce": nonce.hex(),
        "version": 1
    })


@app.route("/api/sync")
def sync():
    key = sha256(
        b"GhostProtocol-Sync" +
        INSTANCE_SECRET
    )

    plaintext = (
        b"GP-SYNC-V3|" +
        INSTANCE_SECRET[10:26]
    )

    padder = padding.PKCS7(128).padder()

    padded = (
        padder.update(plaintext) +
        padder.finalize()
    )

    iv = secrets.token_bytes(16)

    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )

    encryptor = cipher.encryptor()

    ciphertext = (
        encryptor.update(padded) +
        encryptor.finalize()
    )

    return jsonify({
        "algorithm": "AES-CBC",
        "block_size": 16,
        "iv": iv.hex(),
        "ciphertext": ciphertext.hex(),
        "hint": "the synchronization endpoint leaks padding validity",
        "version": 3
    })


@app.route("/api/sync/check", methods=["POST"])
def sync_check():
    try:
        data = request.get_json(force=True)

        iv = bytes.fromhex(data["iv"])
        ciphertext = bytes.fromhex(data["ciphertext"])

        key = sha256(
            b"GhostProtocol-Sync" +
            INSTANCE_SECRET
        )

        plaintext = aes_cbc_decrypt(
            iv,
            ciphertext,
            key
        )

        pkcs7_unpad(plaintext)

        return jsonify({
            "valid": True
        })

    except Exception:
        return jsonify({
            "valid": False
        })


@app.route("/api/final")
def final():
    shard_hex = request.args.get("shard", "")

    try:
        shard = bytes.fromhex(shard_hex)
    except ValueError:
        return jsonify({
            "status": "rejected"
        }), 400

    if len(shard) != 16:
        return jsonify({
            "status": "rejected"
        }), 400

    if shard != INSTANCE_SECRET[10:26]:
        return jsonify({
            "status": "rejected"
        }), 403

    suffix = INSTANCE_SECRET[26:32]

    relation = bytes(
        suffix[i] ^ shard[(i * 7) % 16]
        for i in range(6)
    )

    return jsonify({
        "status": "accepted",
        "next": "/api/flag",
        "relation": relation.hex(),
        "relation_description":
            "suffix[i] XOR shard[(7*i) mod 16]"
    })


@app.route("/api/flag")
def flag():
    shard_hex = request.args.get("shard", "")
    challenge = request.args.get("challenge", "")

    try:
        shard = bytes.fromhex(shard_hex)
        relation = bytes.fromhex(challenge)
    except ValueError:
        return jsonify({
            "status": "rejected"
        }), 400

    if len(shard) != 16 or len(relation) != 6:
        return jsonify({
            "status": "rejected"
        }), 400

    if shard != INSTANCE_SECRET[10:26]:
        return jsonify({
            "status": "rejected"
        }), 403

    suffix = INSTANCE_SECRET[26:32]

    expected_relation = bytes(
        suffix[i] ^ shard[(i * 7) % 16]
        for i in range(6)
    )

    if relation != expected_relation:
        return jsonify({
            "status": "rejected"
        }), 403

    flag_material = hashlib.sha256(
        b"GhostProtocol-Final" +
        INSTANCE_SECRET
    ).hexdigest()

    return jsonify({
        "status": "accepted",
        "flag": f"FLAG{{{flag_material[:32]}}}"
    })


# ---------------------------------------------------------
# Start
# ---------------------------------------------------------

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))

    app.run(
        host="0.0.0.0",
        port=port
    )
