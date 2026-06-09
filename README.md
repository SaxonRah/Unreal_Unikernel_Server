## UE5 Unikernel Server - Project Outline

### Origin

In October 2016, I proposed on the Epic Developer Community Forums that an Unreal Engine dedicated server could potentially run as a unikernel using IncludeOS: booting directly into the game server without a conventional host operating system, with a smaller footprint, faster boot time, and a reduced attack surface.

Tim Sweeney replied that the idea was "very interesting," but the concept was ahead of the tooling. IncludeOS required the application to be built specifically for its environment, and the UE4 dedicated server had a large dependency footprint: threading, complex file I/O, a substantial C/C++ runtime, networking, and broad POSIX-like behavior. At the time, running the full engine server this way was not realistic.

### Why It Did Not Happen Then

The original idea was to run the actual UE dedicated server as the unikernel payload. That meant porting or adapting a very large existing Linux-style server program to a minimal unikernel runtime.

IncludeOS was powerful, but it was not a drop-in Linux binary runtime. You were effectively building for IncludeOS, not simply taking an existing dedicated server executable and booting it. UE4’s server-side dependency surface made that a long-term research project rather than a practical near-term prototype.

### What Changed

The better modern target is NanoS from NanoVMs.

Instead of requiring the application to be rewritten around a unikernel API, NanoS is designed to run existing Linux ELF binaries as single-application virtual machines. It has a more practical tooling story through `ops`, supports normal C/C++ Linux-style programs, and is a better fit for testing small network services as unikernels.

That changes the shape of the project. The goal no longer has to be "run the full UE5 dedicated server as a unikernel." A better first step is to build a tiny custom UE-compatible network endpoint.

### The Evolved Idea

The proof of concept is a small C++ UDP service that implements just enough of the UE5 connection path to make an unmodified UE5 client complete its initial connection sequence.

This service would not embed UE5. It would not link the UE5 SDK. It would not load maps, run gameplay code, replicate actors, or simulate a world.

Instead, it would act as a minimal UE-compatible handshake and login endpoint:

1. Complete the UE5 StatelessConnect handshake.
2. Accept the initial control-channel login sequence.
3. Send the minimum valid response needed for the client to reach the "connected" state.
4. Keep the connection alive long enough to prove that a UE-compatible endpoint can run as a tiny unikernel payload.

The unikernel binary would be the server endpoint itself: no general-purpose OS, no shell, no package manager, no SSH daemon, and no exposed services beyond the UDP code required for the experiment.

### What the Endpoint Must Implement

UE5’s initial connection flow has two major pieces, both over UDP.

#### Phase 1 - StatelessConnect Handshake

UE uses a stateless, DTLS-inspired challenge-response handshake. The server sends a cookie challenge. The client echoes the cookie. The server validates it without needing to keep persistent per-client state between the first packets.

For the PoC, the endpoint needs to reproduce the relevant cookie generation and validation behavior closely enough that a stock UE5 client accepts the handshake.

#### Phase 2 - Control Channel Login

After the packet handler handshake, the client enters the early control-channel flow. At a high level, this includes messages such as:

* `NMT_Hello`
* `NMT_Challenge`
* `NMT_Login`
* `NMT_Welcome`

The key milestone is `NMT_Welcome`. Once the client receives a valid welcome response, the experiment has proven that a tiny non-UE binary can impersonate enough of a UE server endpoint to complete the first connection phase.

### Important Scope Boundary

This is not yet a replacement for a real UE5 dedicated server.

After `NMT_Welcome`, a normal UE client still expects server-shaped network behavior: packet sequencing, reliability, channel state, package map behavior, actor channels, NetGUID handling, keepalives, and eventually replication. Two UE clients cannot simply be connected back-to-back as raw UDP peers and be expected to behave like a real server/client session, because UE networking is not symmetric at that layer.

So the first milestone is narrower and cleaner:

> Can a tiny C++ program, running as a NanoS unikernel, make an unmodified UE5 client complete the initial server connection path?

If yes, that proves the foundation.

### The Stack

* **Language:** C++
* **Target:** Small Linux ELF binary
* **Runtime:** NanoS unikernel
* **Build/deploy tool:** `ops`
* **Transport:** UDP
* **Dependencies:** libc plus a small HMAC/SHA1 implementation, ideally inline or statically linked
* **Reference code:** UE5 source, especially `StatelessConnectHandlerComponent.cpp`, `NetDriver.cpp`, `NetworkConnection.cpp`, and the control-message serialization path
* **Expected binary size:** roughly 100–200 KB for the first prototype, depending on libc and crypto choices
* **Local hypervisor:** KVM
* **Cloud target:** NanoS image deployed as a small VM on a major cloud provider

### Proof of Concept Goal

The PoC succeeds when an unmodified UE5 client can connect to a tiny NanoS-hosted binary and complete the initial UE5 connection sequence through `NMT_Welcome`.

The target result:

* A small C++ ELF binary
* Booted directly as a NanoS unikernel
* Listening on a UE-compatible UDP port
* Completing the StatelessConnect handshake
* Completing the minimal control-channel login path
* Keeping the client connection alive long enough to verify the endpoint behavior
* Booting in well under a second, ideally near the tens-of-milliseconds range on local KVM

If this works, it demonstrates that at least part of a UE-compatible game server endpoint can be reduced to a tiny unikernel service. That opens the door to a new class of lightweight game infrastructure: tiny connection brokers, match handoff endpoints, relay nodes, security filters, replay collectors, or eventually specialized minimal servers that implement only the subset of UE networking required for a specific game mode.

The long-term vision is not necessarily to unikernelize the entire Unreal Engine server. The more interesting possibility is to split the problem apart: identify which parts of the UE server protocol actually need the full engine, and which parts can be replaced by tiny, purpose-built, fast-booting unikernel services.
