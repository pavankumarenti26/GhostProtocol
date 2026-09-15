# 👻 Ghost Protocol

> **Something is wrong with the document service.**
>
> The system says everything is operational.
> The artifact looks harmless.
> The cryptography looks familiar.
>
> But somewhere inside the protocol...
>
> **there is a ghost.**

---

## 🎯 Objective

Find the flag.

That's it.

No source code is provided during the challenge.  
No secrets are handed to you.

Investigate the service, understand the artifact, and follow the trail.

---

## 🛰️ The Challenge

**Ghost Protocol** is a multi-stage CTF challenge combining:

- 🔎 Web Recon
- 🧩 Custom VM / Reverse Engineering
- 🔐 Cryptography
- 📡 Protocol Analysis
- 🧠 Logic & Exploitation

Every stage gives you just enough information to reach the next one.

Miss something?

You may be staring directly at the answer without realizing it.

---

## 🚪 Starting Point

The service exposes a small API.

Begin with:

`/api/status`

Then start looking for things the application was never supposed to make interesting.

---

## 🗺️ Your Mission

Think of the challenge as a chain:

```text
        ┌─────────────┐
        │   Web API   │
        └──────┬──────┘
               │
               ▼
        ┌─────────────┐
        │   Artifact  │
        └──────┬──────┘
               │
               ▼
        ┌─────────────┐
        │  Custom VM  │
        └──────┬──────┘
               │
               ▼
        ┌─────────────┐
        │    Crypto   │
        └──────┬──────┘
               │
               ▼
        ┌─────────────┐
        │    Sync     │
        └──────┬──────┘
               │
               ▼
        ┌─────────────┐
        │    Ghost    │
        └──────┬──────┘
               │
               ▼
          🚩 FLAG 🚩
