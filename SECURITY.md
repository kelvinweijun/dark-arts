# Dark Arts — Security Policy

## Scope

Dark Arts is a command-and-control (C2) framework built for **laboratory research and authorized security testing only**. This document describes its security architecture, threat model, cryptographic guarantees, known limitations, and how to report vulnerabilities.

**Unauthorized use of this software against systems you do not own or have explicit written permission to test is illegal and unethical.**

---

## Supported Versions

| Version | Supported |
|---------|-----------|
| `0.1.0-dev` (current) | Yes |

---

## Reporting Vulnerabilities

If you discover a security vulnerability in this framework:

1. **Do not** open a public GitHub issue.
2. Email the maintainers at the address listed in the repository profile.
3. Include a description of the vulnerability, affected component, and reproduction steps.
4. Allow reasonable time for a fix before any public disclosure.

---

## Architecture Overview

```
                  ┌──────────┐
                  │  console  │  operator REPL
                  └────┬─────┘
                       │ REST API (bearer auth)
                  ┌────▼─────┐
                  │  server   │  session manager, task queue, result store
                  └────┬─────┘
                       │ encrypted blobs
                  ┌────▼─────┐
                  │   edge    │  stateless HTTPS ingress (nginx cover)
                  └────┬─────┘
                       │ ciphertext only
            ┌──────────┼──────────┐
            │          │          │
       ┌────▼───┐ ┌───▼────┐ ┌──▼───┐
       │ relay1  │ │ relay2 │ │ ...  │  LAN mesh forwarders
       └────┬───┘ └───┬────┘ └──┬───┘
            │         │         │
       ┌────▼─────────▼─────────▼───┐
       │          beacon(s)          │  implant on target
       └────────────────────────────┘

  Dead drops (DNS TXT, file, gist) — passive rendezvous for stager
  MinIO/S3 — encrypted blob storage backend
```

### Component Summary

| Component | Role | Sees Plaintext? | Persistent State |
|-----------|------|-----------------|------------------|
| `edge` | Stateless blob ingress/egress | No | None |
| `server` | Session manager, task queue, API | Yes (tasking content) | Session ratchets, task queue |
| `relay` | LAN mesh forwarder | No (ciphertext only) | Ephemeral peer cache |
| `beacon` | Implant on target | Yes (executed commands) | Session keys in memory |
| `console` | Operator interface | Yes | UI state |
| `stager` | First-stage fetcher | No | None |

---

## Cryptographic Design

### Key Hierarchy

| Key Type | Algorithm | Purpose | Lifetime |
|----------|-----------|---------|----------|
| **Identity** | X25519 ECDH | Derive shared secrets per session | Long-term (seed-derived) |
| **Session** | X25519 + HKDF | Per-session symmetric keys | One session (forward secrecy) |
| **Operator signing** | Ed25519 | Sign task payloads and stage drops | Long-term (air-gapped) |
| **AEAD** | ChaCha20-Poly1305 | Encrypt all wire traffic | Per-message (ratcheted) |

### Forward Secrecy

Each session performs an X25519 ECDH key agreement. The shared secret is fed into an HKDF ratchet that produces new send/recv keys per message. Compromise of a session key does not expose past messages.

### Replay Detection

A 256-counter sliding window detects replayed envelopes. Out-of-order delivery is tolerated within the window. Counter gaps from crash/restart recovery are handled by re-deriving from the last known counter.

### Message Format

All wire messages use a versioned `MessageEnvelope`:

```
{
  "v":     1,
  "nonce": "<base64>",
  "ct":    "<base64 ciphertext>",
  "sig":   "<base64 ed25519 signature>"
}
```

The `ct` field is a ChaCha20-Poly1305 AEAD ciphertext. The `sig` field is an optional Ed25519 signature over the envelope for operator authentication.

---

## Threat Model

### Adversary Classes

| Adversary | Goal | Mitigation |
|-----------|------|------------|
| Network observer / DPI | Detect C2 channel | Protocol mimicry (browser UA rotation, nginx cover pages), AEAD-only wire format, polymorphic jitter |
| Endpoint EDR/AV | Kill implant, capture keys | In-memory-only keys, XOR sleep masking, AMSI/ETW patching, direct syscalls bypass user-mode hooks |
| Seized edge server | Recover sessions, identify operator | Edge is stateless, sees no plaintext, no operator data |
| Seized C2 server | Recover blobs | Blobs encrypted under operator-held keys; server only stores ciphertext |
| Seized operator machine | Impersonate operator | Ed25519 signing keys are air-gapped / HSM-stored |
| Dead-drop poisoning | Feed implant bad stage | Ed25519 signature on every drop payload; verified before execution |

### Trust Boundaries

1. **Implant ↔ Infrastructure:** All tasking and results are AEAD-encrypted end-to-end. Edge and relay never see plaintext.
2. **Target LAN ↔ Egress:** Only relays cross this boundary. Beacons never need direct internet access.
3. **Dead drops:** Semi-public channels. Never contain plaintext or operator identifiers. Content is encrypted and rotated.
4. **Operator ↔ Server:** Bearer-token authentication. Server sees tasking content but cannot forge operator signatures.

---

## Security Controls

### Evasion (Anti-Analysis)

**Direct syscalls** (`pkg/evasion`):
- Resolves Nt* syscall numbers from a clean `\KnownDlls\ntdll.dll` section mapping.
- Issues syscalls via an ABI0 assembler trampoline — no ntdll stub call, no syscall-site scanning.
- Neutralizes in-memory API hooks (EDR user-mode detours) via KnownDlls-based unhooking (UDRL).

**Sleep masking** (`pkg/sleepmask`):
- XOR-encrypts crypto session state and registered memory regions during sleep cycles.
- Dedicated non-heap XOR-key page with `PAGE_NOACCESS` when idle.
- Registered regions (e.g., injected shellcode pages) are XORed and set to `PAGE_NOACCESS`.

**Traffic mimicry** (`pkg/mimic`):
- Browser User-Agent rotation across Windows/macOS/Linux Chrome, Edge, Firefox, Safari.
- Realistic HTTP headers applied to all beacon requests.
- Edge server responds with `Server: nginx` header and configurable cover pages.

### Security Control Bypass (`pkg/securityctl`)

**AMSI bypass:**
- Patches `AmsiScanBuffer` in `amsi.dll` at runtime.
- Loads the DLL via `LoadLibraryW`, resolves the export, and overwrites the entry point.
- Patch: dereferences the 6th argument (`AMSI_RESULT *result`) and writes `AMSI_RESULT_CLEAN` (0).
- Clean original bytes sourced from a fresh `\KnownDlls\amsi.dll` section mapping for accurate restore.
- Original page protection preserved and restored after patch/unpatch.

**ETW bypass:**
- Patches `EtwEventWrite` in `ntdll.dll` similarly.
- Zeros the return value (EAX = `ERROR_SUCCESS`) and returns immediately.
- Does not touch R9 (ETW's 4th parameter is `PEVENT_DATA_DESCRIPTOR UserData`, not an output).

**Patcher hardening:**
- 7 randomized AMSI patch variants and 7 ETW variants (4 unique zeroing patterns each).
- Timing jitter (100μs–5ms) between operations.
- `0xCC` (int3) padding instead of NOP sleds.
- `VirtualQuery` reads actual page protection; restored to original value after patch/unpatch.
- Lifecycle state machine prevents double-patch or restore-before-patch.
- All operations are concurrency-safe (single `baseControl.mu` per instance).
- `FreeLibrary` called only if the module was already resident (avoids unloading DLLs we loaded).

### In-Memory Execution

**Reflective DLL loader** (`pkg/reflective`):
- Maps Windows x64 PE DLLs from memory without `LoadLibrary`, disk writes, or loader-lock.
- Manual IAT import resolution and `IMAGE_REL_BASED_DIR64` relocation processing.
- Sleep-mask integration for code-page XOR protection.

**Beacon Object File (BOF) engine** (`pkg/bof`):
- Parses COFF headers, sections, symbols, and relocations.
- Resolves external symbols to in-process Beacon API trampolines.
- Loads sections into executable memory via `NtProtectVirtualMemory`.
- ABI0 assembler bridge handles Win64 calling convention.

**Shellcode injection** (`pkg/inject`):
- Position-independent x64 shellcode execution via evasion syscalls.
- Self-injection and remote-process injection modes.
- RX pages registered with sleep mask for XOR protection.

### Key Management

- **Identity keys:** Derived from a 32-byte seed via X25519 ECDH. Seed baked at build time via `-ldflags`.
- **Operator signing keys:** Ed25519, derived from a separate seed. Should be air-gapped or HSM-stored in production.
- **Session keys:** Ephemeral per session. Forward secrecy via HKDF ratchet.
- **No keys on disk:** Session keys exist only in beacon memory. Server stores session ratchet state (counters), not keys.

### Persistence Mechanisms

- **Registry run key:** `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
- **Scheduled tasks:** Via `schtasks /create`
- **Startup folder:** `.cmd` files in `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`
- **UAC elevation:** 5 methods — `daily` (zero-prompt on Win11 24H2+), `schtasks`, `cmluautil`, `fodhelper`, `computerdefaults`

All persistence methods are reversible via `unpersist` task.

---

## Build Security

### Reproducible Builds

```bash
# Build with baked-in configuration
go build -ldflags "-X dark-arts/internal/version.Version=0.1.0 \
  -X main.seed=<64-hex> \
  -X main.serverPub=<hex>" \
  ./cmd/beacon
```

### Build Tags

| Tag | Effect |
|-----|--------|
| `inject` | Enables shellcode injection via evasion syscalls |
| `windows,amd64` | Enables all Windows-specific security controls |

### CI Pipeline

GitHub Actions runs on every push:
- `go vet ./...` — static analysis
- `go test -race ./...` — race detector
- `gofmt` check — code formatting

---

## Known Limitations

1. **AMSI/ETW bypasses are user-mode only.** Kernel-level callbacks (`PsSetLoadImageNotifyRoutine`, `ObRegisterCallbacks`, kernel ETW providers) cannot be intercepted from user mode.

2. **AMSI functional test skips on this machine.** AMSI returns `E_INVALIDARG` (0x80070057) for Go test binaries — the test harness is not inspected by AMSI. Real contract verification requires running in a process AMSI actually monitors.

3. **`Restore()` does not report errors.** The interface returns `void`; if restoration fails, the caller has no way to know the process may still contain modified function bytes.

4. **Sleep masking is XOR-based.** A memory forensics tool that knows the XOR-key page location can decrypt masked regions. The key page is set to `PAGE_NOACCESS` when idle but is still physically mapped.

5. **Persistence is filesystem/registry-based.** Advanced EDR solutions that monitor `HKCU\...\Run`, scheduled tasks, or startup folders will detect the persistence mechanism.

6. **Beacon config is baked at build time.** Changing server addresses or seeds requires recompilation. Runtime configuration via tasking is limited to sleep interval.

7. **Edge server is stateless.** It cannot enforce rate limits or reject replayed blobs at the application layer (replay protection is at the crypto layer).

---

## Residual Risks

| Risk | Mitigation | Remaining Exposure |
|------|------------|-------------------|
| Physical seizure of active operator machine | HSM/air-gapped keys | Operator session state in memory |
| Memory forensics on beacon | Sleep masking (XOR) | XOR key page location discoverable |
| Dead-drop takedown | Multi-drop fallback, rotation | Beacon stalls until next rotation |
| Network fingerprinting | UA rotation, nginx cover | Behavioral analysis over time |
| Kernel-level EDR | Not addressed (user-mode only) | Kernel callbacks can still detect |
| Build artifact attribution | Source-level concern | Compiler/toolchain metadata |

---

## Regulatory Notice

This software is provided for **authorized security research and laboratory use only**. Users are responsible for ensuring compliance with all applicable laws and regulations. The authors assume no liability for misuse.
