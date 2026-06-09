#pragma once

#include <netinet/in.h>
#include <stdint.h>

#include <array>
#include <vector>

namespace ue574 {

static constexpr const char *TargetVersion = "Unreal Engine 5.7.4";

static constexpr uint8_t HandshakeVersionOriginal = 0;
static constexpr uint8_t HandshakeVersionRandomized = 1;
static constexpr uint8_t HandshakeVersionNetCLVersion = 2;
static constexpr uint8_t HandshakeVersionSessionClientId = 3;
static constexpr uint8_t HandshakeVersionNetCLUpgradeMessage = 4;
static constexpr uint8_t HandshakeVersionLatest = 4;

static constexpr uint8_t HandshakeTypeInitial = 0;
static constexpr uint8_t HandshakeTypeChallenge = 1;
static constexpr uint8_t HandshakeTypeResponse = 2;
static constexpr uint8_t HandshakeTypeAck = 3;
static constexpr uint8_t HandshakeTypeRestartHandshake = 4;
static constexpr uint8_t HandshakeTypeRestartResponse = 5;
static constexpr uint8_t HandshakeTypeVersionUpgrade = 6;

static constexpr uint32_t SessionIdBits = 2;
static constexpr uint32_t ClientIdBits = 3;
static constexpr size_t CookieSize = 20;

enum class PacketKind {
  Unknown,

  // Temporary self-test harness.
  TempHandshakeInitial,
  TempHandshakeResponse,
  TempControlHello,
  TempControlLogin,

  // Real UE5.7.4 stateless handshake packets.
  UEHandshakeInitial,
  UEHandshakeResponse,
  UEHandshakeOther,

  // Future layer after handshake.
  ProbablyUEPostHandshakeDatagram,
};

enum class SessionPhase {
  CookieValidated,
  SawHello,
  Welcomed,
};

struct UEHandshake {
  bool recognized = false;
  uint8_t session_id = 0;
  uint8_t client_id = 0;
  bool restart = false;
  uint8_t remote_min_version = 0;
  uint8_t remote_cur_version = 0;
  uint8_t packet_type = 0;
  uint8_t remote_sent_count = 0;
  uint32_t network_version = 0;
  uint16_t network_features = 0;
  uint8_t secret_id = 0;
  double timestamp = 0.0;
  std::array<uint8_t, CookieSize> cookie{};
};

struct ParsedPacket {
  PacketKind kind = PacketKind::Unknown;
  UEHandshake handshake{};
};

const char *session_phase_name(SessionPhase p);
const char *packet_kind_name(PacketKind p);
const char *handshake_type_name(uint8_t t);

ParsedPacket parse_datagram(const sockaddr_in &from, const uint8_t *data,
                            size_t n);

// Temporary harness builders.
std::vector<uint8_t> build_temp_handshake_challenge(const sockaddr_in &to);
bool validate_temp_handshake_response(const sockaddr_in &from,
                                      const uint8_t *data, size_t n);
std::vector<uint8_t> build_temp_handshake_ok();
std::vector<uint8_t> build_temp_control_challenge();
std::vector<uint8_t> build_temp_welcome();

// Real UE5.7.4 stateless handshake builders.
std::vector<uint8_t> build_ue574_initial(uint8_t client_id,
                                         uint32_t network_version,
                                         uint16_t network_features);
std::vector<uint8_t> build_ue574_response(const UEHandshake &challenge);
//
// These are packet builders for the protocol shape observed in the
// UE5.7.4 source files. They intentionally do not copy Epic source.
std::vector<uint8_t> build_ue574_challenge(const sockaddr_in &to,
                                           const UEHandshake &initial);
bool validate_ue574_response(const sockaddr_in &from,
                             const UEHandshake &response);
std::vector<uint8_t> build_ue574_ack(const UEHandshake &response);

// Low-level parser exposed for tests/tools.
UEHandshake try_parse_ue574_handshake(const uint8_t *data, size_t n);

} // namespace ue574
