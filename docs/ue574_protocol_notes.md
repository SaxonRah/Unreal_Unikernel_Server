# UE5.7.4 StatelessConnect Notes

This project is based on the uploaded UE5.7.4 files:

- `StatelessConnectHandlerComponent.h`
- `StatelessConnectHandlerComponent.cpp`
- `PacketHandler.h`
- `PacketHandler.cpp`
- `NetConnection.h`
- `NetConnection.cpp`
- `DataChannel.cpp`

## Handshake versions

```text
0 Original
1 Randomized
2 NetCLVersion
3 SessionClientId
4 NetCLUpgradeMessage / Latest
```

## Handshake packet types

```text
0 Initial
1 Challenge
2 Response
3 Ack
4 RestartHandshake
5 RestartResponse
6 VersionUpgrade
```

## Prefix for latest packets

```text
SessionID:          2 bits
ClientID:           3 bits
bHandshakePacket:   1 bit
bRestartHandshake:  1 bit
MinVersion:         8 bits
CurVersion:         8 bits
PacketType:         8 bits
SentCount:          8 bits
NetworkVersion:    32 bits
NetworkFeatures:   16 bits
```

For Initial / Challenge / Response / Ack, the body then contains:

```text
SecretId:           1 bit
Timestamp:         64 bits, double
Cookie:           160 bits, 20 bytes
RandomData:        64..128 bits
TerminationBit:     1 bit
```

Initial uses `SecretId=0`, `Timestamp=0.0`, and a zero filler cookie-sized field.
Challenge uses a positive timestamp and a 20-byte cookie.
Response echoes the Challenge timestamp, secret id, and cookie.
Ack uses a negative timestamp and echoes the accepted cookie.

## Cookie note

UE's server derives the 20-byte cookie from a rotating server secret and serialized
client address/timestamp. The client does not need to know that algorithm; it only
echoes the cookie. This standalone endpoint therefore uses its own HMAC and validates
against itself.

The cookie's first two int16 values matter because the UE client extracts initial
packet sequence values from the accepted cookie after Ack. This implementation seeds
those first four bytes deliberately instead of leaving them random.

## Next layer

Once Ack succeeds, normal NetConnection traffic begins. That is a separate protocol
layer from StatelessConnect and must be implemented next.
