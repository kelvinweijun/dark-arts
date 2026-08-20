# Dark Arts — Threat Model (Phase 0)

Scope: laboratory-only C2 framework. This document captures what we protect, from whom, the data flows, trust boundaries, and component-seizure analysis. It is a living document; update it whenever a phase adds components or channels.

## Components

| Component | Role | State kept | Network access |
|---|---|---|---|
| `edge` | Stateless ingress; AEAD-authenticated receive; writes ciphertext blobs | none (scale-to-zero) | egress network |
| `server` | Session manager, tasking queue, result store, API for console | session ratchet state, queue, blob index | egress network |
| `minio` | Object store; encrypted blobs only | blobs, bucket metadata | egress network |
| `console` | Operator UI, operation killchains, audit log | UI state | server API only |
| `beacon` | Implant (tasked side) | session keys in memory only | dead drops / edge / relays |
| `stager` | First stage; fetches beacon | none | dead drops only |
| `relay` | Mesh forwarder inside target network | ephemeral peer cache | LAN only |
| dead drops (DNS TXT, gist, file) | Passive rendezvous; no server presence | published ciphertext | passive read |

## Trust boundaries

1. Implant <-> operator infrastructure: the only boundary carrying plaintext command intent — but still AEAD-encrypted end-to-end; edge/server never see plaintext tasking.
2. Target LAN <-> egress: only relays/egress beacons cross it.
3. Operator machine <-> server: authentication via mTLS or OIDC SSO (Phase 4).
4. Dead drops are semi-public: never contain plaintext or operator identifiers; content is encrypted and rotated.

## Data flows

- Tasking: console -> server (authed) -> object store -> edge (beacon poll) -> beacon (verify sig) -> relay mesh (optional).
- Results: beacon -> edge -> object store -> server -> console.
- Rendezvous: beacon polls dead drop (e.g., DNS TXT) for signed, encrypted stage/rotation instructions.

## Adversary classes and mitigations

| Adversary | Goal | Mitigation (phase) |
|---|---|---|
| Network observer / DPI | detect C2 channel | protocol mimicry engine (8), polymorphic jitter (8), AEAD-only wire format (1) |
| Endpoint EDR/AV | kill implant, capture keys | in-memory-only keys (6), anti-forensics basics (6), small staged loader (5) |
| Seized edge | recover sessions/identify operator | edge is stateless, sees no plaintext, no operator data (3) |
| Seized server/minio | recover blobs | blobs encrypted under operator-held keys; server keys minimal and derivable-only (4, 10.3) |
| Seized operator machine | impersonate operator | HSM/operator key separation (10.3), RBAC + per-op ACLs (9) |
| Drop operator / poisoning | feed implant bad stage | operator ed25519 signature on every drop payload (1, 2) |

## Key separation

- Operator identity keys: ed25519, HSM/air-gapped; signs tasks and drops. Never stored server-side.
- Session keys: X25519 ECDH per session, HKDF-ratcheted; forward secrecy (1.1).
- Blob encryption keys: derived per session; held by server at rest encrypted under operator key; cleared on teardown.

## Assumptions and constraints

- Lab-only deployment (containers, test accounts, fake DNS). No real-network use without written authorization and per applicable law.
- Teardown is a first-class operation: rotate dead drops, purge object store, destroy session state.

## Residual risks

- Physical seizure of an active, unlocked operator workstation (HSM mitigates).
- Implant side-channel leakage in memory forensics (partially mitigated in Phase 6; re-test in Phase 10).
- Dead-drop takedown causing beacon stalls (mitigated by rotation + multi-drop fallback, Phase 2).
