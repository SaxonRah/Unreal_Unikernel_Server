#pragma once

#include <netinet/in.h>
#include <stdint.h>

#include <array>
#include <vector>

namespace ue574 {

static constexpr const char *TargetVersion = "Unreal Engine 5.7.4";

enum class PacketKind {
  Unknown,
  TempHandshakeInitial,
  TempHandshakeResponse,
  TempControlHello,
  TempControlLogin,

  // Heuristic only. Real decode requires filling in the UE5.7.4 serializer.
  ProbablyUEPacketHandlerDatagram,
};

enum class SessionPhase {
  CookieValidated,
  SawHello,
  Welcomed,
};

struct ParsedPacket {
  PacketKind kind = PacketKind::Unknown;
};

const char *session_phase_name(SessionPhase p);

ParsedPacket parse_datagram(const sockaddr_in &from, const uint8_t *data,
                            size_t n);

// Temporary harness builders.
std::vector<uint8_t> build_temp_handshake_challenge(const sockaddr_in &to);
bool validate_temp_handshake_response(const sockaddr_in &from,
                                      const uint8_t *data, size_t n);
std::vector<uint8_t> build_temp_handshake_ok();
std::vector<uint8_t> build_temp_control_challenge();
std::vector<uint8_t> build_temp_welcome();

// UE5.7.4 replacement seams.
//
// These are intentionally separate from the temp harness.
// Implement these from a licensed 5.7.4 source:
//   Engine/Source/Runtime/Engine/Private/PacketHandlers/StatelessConnectHandlerComponent.cpp
//   Engine/Source/Runtime/Engine/Public/PacketHandlers/StatelessConnectHandlerComponent.h
//   Engine/Source/Runtime/PacketHandlers/PacketHandler/Private/PacketHandler.cpp
//   Engine/Source/Runtime/Engine/Private/NetConnection.cpp
//   Engine/Source/Runtime/Engine/Private/DataChannel.cpp
//   Engine/Source/Runtime/Engine/Classes/Engine/NetConnection.h
//
// Do not paste Epic source here. Reimplement the wire format a local licensed
// copy.

struct UE574DecodeResult {
  bool recognized = false;
  bool needs_handshake_reply = false;
  bool needs_control_reply = false;
};

UE574DecodeResult try_decode_ue574_packet(const uint8_t *data, size_t n);

} // namespace ue574
