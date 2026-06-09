# UE5.7.4 Protocol Implementation Notes

## Why this file exists

Epic's public API docs identify the relevant classes and source paths, but the exact wire behavior must be derived from your licensed UE5.7.4 source tree and packet captures.

The project should remain a clean-room implementation: use the source as a behavioral reference, do not paste Epic code.

## Working hypothesis

The first real milestone is:

```text
client real StatelessConnect initial packet
server valid StatelessConnect challenge
client challenge response
server accepts and enters normal NetConnection/control-channel path
```

The second milestone is:

```text
NMT_Hello
NMT_Challenge
NMT_Login
NMT_Welcome
```

## Do not overbuild yet

Do not implement actor channels, NetGUIDs, replication, package map, or movement. The current proof is only "can a tiny non-UE ELF act like the first server endpoint long enough to welcome a client?"

## Recommended capture setup

```bash
sudo tcpdump -i any udp port 7777 -w ue574-connect-attempt.pcap
./build/ue574_endpoint --port 7777 --binlog packets.binlog
```

Then attempt:

```text
open 127.0.0.1:7777
```

from a UE5.7.4 client or packaged test project.

## Implementation order

1. Identify the exact first-packet marker/fields from StatelessConnectHandlerComponent.
2. Implement server challenge builder.
3. Implement client challenge-response validator.
4. Add just enough PacketHandler post-handshake framing to see control-channel open.
5. Implement minimal control message reader/writer.
6. Send NMT_Welcome.
