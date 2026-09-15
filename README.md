# Ghost Protocol

A multi-stage cryptographic and reverse-engineering CTF challenge.

## Challenge Chain

Recon
- Hidden API
- Custom GP91 binary
- Custom VM
- Stage derivation
- AES-GCM nonce reuse
- CBC padding oracle
- Final cryptographic stage
- FLAG

## Requirements

- Docker Desktop
- Python 3.12+
- Git
- Python requests package

## Run Locally

Build the image:

    docker build -t ghost-protocol .

Run the challenge:

    .\run_team.ps1 -Team team01 -Port 5000

The service will be available at:

http://localhost:5000

## Artifact

The challenge artifact is:

artifact/gp-core-0917.bin

It uses the custom GP91 binary format and contains code executed by a custom virtual machine.

## Intended Skills

- Web reconnaissance
- Endpoint discovery
- Binary analysis
- Reverse engineering
- Custom VM analysis
- Hash-chain reasoning
- AES-GCM nonce-reuse exploitation
- CBC padding-oracle exploitation
- Cryptographic protocol analysis

## Objective

Progress through the protocol and recover the final flag.

Each stage provides information required to reach the next stage.

## Rules

Only interact with infrastructure explicitly provided for this challenge.

Do not attack unrelated systems, services, accounts, or infrastructure.

Do not attempt to access other teams' challenge instances.

Good luck.

---

Ghost Protocol
