from flask import Flask, jsonify, request, send_from_directory
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import hashlib
import os

app = Flask(__name__)

ARTIFACT_DIR = "/app/artifact"
SECRET_PATH = os.environ.get("INSTANCE_SECRET", "/app/instance/secret.bin")
PUBLIC_SEED = bytes.fromhex(os.environ.get("PUBLIC_SEED", ""))
VM_STATE = bytes.fromhex(os.environ.get("VM_STATE", ""))

with open(SECRET_PATH, "rb") as f:
    INSTANCE_SECRET = f.read()

if len(INSTANCE_SECRET) != 32:
    raise RuntimeError("INSTANCE_SECRET must be exactly 32 bytes")

if len(PUBLIC_SEED) != 16:
    raise RuntimeError("PUBLIC_SEED must be exactly 16 bytes")


# ============================================================
# Internal cryptographic state
# ============================================================

def stage_value():
    return hashlib.sha256(
        b"GhostProtocol-PublicStage" +
        PUBLIC_SEED +
        VM_STATE
    ).digest()


def private_key():
    return hashlib.sha256(
        b"GhostProtocol-PrivateStage" +
        INSTANCE_SECRET +
        stage_value()
    ).digest()


# ============================================================
# Recon
# ============================================================

@app.get("/")
def index():
    return jsonify({
        "service": "document-service",
        "status": "operational"
    })


@app.get("/api/status")
def status():
    return jsonify({
        "service": "document-service",
        "status": "operational"
    })


# ============================================================
# Artifact discovery
# ============================================================

@app.get("/api/artifact")
def artifact():
    artifact_id = request.args.get("id", "")

    if artifact_id != "gp-core-0917":
        return jsonify({"error": "artifact not found"}), 404

    return jsonify({
        "id": artifact_id,
        "location": "/artifacts/gp-core-0917.bin",
        "format": "GP91"
    })


@app.get("/artifacts/<path:name>")
def artifacts(name):
    if name != "gp-core-0917.bin":
        return jsonify({"error": "not found"}), 404

    return send_from_directory(
        ARTIFACT_DIR,
        name,
        as_attachment=True
    )


# ============================================================
# Stage 1
# ============================================================

@app.get("/api/stage")
def stage():
    supplied = request.args.get("value", "")

    if len(supplied) != 64:
        return jsonify({"error": "invalid stage"}), 403

    expected = stage_value().hex()

    if supplied.lower() != expected:
        return jsonify({"error": "invalid stage"}), 403

    return jsonify({
        "status": "accepted",
        "next": "/api/telemetry"
    })


# ============================================================
# Stage 2
#
# Intentional AES-GCM nonce reuse.
# ============================================================

@app.get("/api/telemetry")
def telemetry():
    key = private_key()

    nonce = hashlib.sha256(
        b"GhostProtocol-Telemetry-Nonce" +
        INSTANCE_SECRET
    ).digest()[:12]

    token = INSTANCE_SECRET[:10]

    prefix = b"GP-TELEMETRY-V1:STAGE=PRIVATE;TOKEN="

    known_plaintext = prefix + token

    protected_plaintext = (
        prefix +
        token +
        b";NEXT=SYNC"
    )

    aes = AESGCM(key)

    known = aes.encrypt(
        nonce,
        known_plaintext,
        b"GP-TELEMETRY-V1"
    )

    protected = aes.encrypt(
        nonce,
        protected_plaintext,
        b"GP-TELEMETRY-V1"
    )

    return jsonify({
        "algorithm": "AES-GCM",
        "known": known.hex(),
        "nonce": nonce.hex(),
        "protected": protected.hex(),
        "version": 1
    })


# ============================================================
# Stage 3
#
# CBC padding oracle.
# ============================================================

SYNC_IV = hashlib.sha256(
    b"GhostProtocol-Sync-IV" +
    INSTANCE_SECRET
).digest()[:16]

SYNC_KEY = hashlib.sha256(
    b"GhostProtocol-Sync-Key" +
    INSTANCE_SECRET
).digest()


def sync_plaintext():
    return (
        b"GP-SYNC-V3|" +
        INSTANCE_SECRET[10:26]
    )


def sync_ciphertext():
    cipher = Cipher(
        algorithms.AES(SYNC_KEY),
        modes.CBC(SYNC_IV)
    )

    encryptor = cipher.encryptor()

    plaintext = sync_plaintext()

    pad_len = 16 - (len(plaintext) % 16)

    plaintext += bytes([pad_len]) * pad_len

    return encryptor.update(plaintext) + encryptor.finalize()


@app.get("/api/sync")
def sync():
    return jsonify({
        "algorithm": "AES-CBC",
        "block_size": 16,
        "ciphertext": sync_ciphertext().hex(),
        "hint": "synchronization failure classification",
        "iv": SYNC_IV.hex(),
        "version": 3
    })


@app.post("/api/sync/check")
def sync_check():
    body = request.get_json(silent=True) or {}

    iv_hex = body.get("iv", "")
    ciphertext_hex = body.get("ciphertext", "")

    try:
        iv = bytes.fromhex(iv_hex)
        ciphertext = bytes.fromhex(ciphertext_hex)
    except ValueError:
        return jsonify({"error": "malformed request"}), 400

    if len(iv) != 16:
        return jsonify({"error": "malformed request"}), 400

    if not ciphertext or len(ciphertext) % 16:
        return jsonify({"error": "malformed request"}), 400

    try:
        cipher = Cipher(
            algorithms.AES(SYNC_KEY),
            modes.CBC(iv)
        )

        decryptor = cipher.decryptor()

        plaintext = (
            decryptor.update(ciphertext) +
            decryptor.finalize()
        )

    except Exception:
        return jsonify({"valid": False})

    if not plaintext:
        return jsonify({"valid": False})

    pad_len = plaintext[-1]

    if pad_len < 1 or pad_len > 16:
        return jsonify({"valid": False})

    if plaintext[-pad_len:] != bytes([pad_len]) * pad_len:
        return jsonify({"valid": False})

    return jsonify({"valid": True})


# ============================================================
# Final stage
#
# The player supplies the recovered 16-byte shard.
#
# The server internally derives the remaining six bytes through
# a rotating relation.  The relation itself is no longer
# disclosed in the response.
#
# This preserves solvability while removing the explicit hint.
# ============================================================

def final_relation(shard):
    suffix = INSTANCE_SECRET[26:32]

    return bytes(
        suffix[i] ^ shard[(i * 7) % 16]
        for i in range(6)
    )


@app.get("/api/final")
def final():
    shard_hex = request.args.get("shard", "")

    try:
        shard = bytes.fromhex(shard_hex)
    except ValueError:
        return jsonify({"error": "invalid proof"}), 403

    if len(shard) != 16:
        return jsonify({"error": "invalid proof"}), 403

    if shard != INSTANCE_SECRET[10:26]:
        return jsonify({"error": "invalid proof"}), 403

    relation = final_relation(shard)

    return jsonify({
        "status": "accepted",
        "challenge": relation.hex()
    })


# ============================================================
# Flag
# ============================================================

@app.get("/api/flag")
def flag():
    shard_hex = request.args.get("shard", "")
    challenge_hex = request.args.get("challenge", "")

    try:
        shard = bytes.fromhex(shard_hex)
        challenge = bytes.fromhex(challenge_hex)
    except ValueError:
        return jsonify({"error": "invalid proof"}), 403

    if len(shard) != 16 or len(challenge) != 6:
        return jsonify({"error": "invalid proof"}), 403

    if shard != INSTANCE_SECRET[10:26]:
        return jsonify({"error": "invalid proof"}), 403

    expected = final_relation(shard)

    if challenge != expected:
        return jsonify({"error": "invalid proof"}), 403

    flag_material = hashlib.sha256(
        b"GhostProtocol-Final" +
        INSTANCE_SECRET
    ).hexdigest()

    return jsonify({
        "status": "complete",
        "flag": f"FLAG{{{flag_material[:32]}}}"
    })


# ============================================================

if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False
    )
