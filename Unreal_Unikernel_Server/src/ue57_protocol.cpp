#include "ue57_protocol.h"

#include "bit_io.h"
#include "crypto_sha1_hmac.h"

#include <string.h>
#include <time.h>

namespace ue574 {

static constexpr uint32_t TempCookieTtlSeconds = 20;
static constexpr uint32_t UECookieTtlSeconds = 40;
static constexpr char CookieSecret[] =
    "CHANGE_ME_FOR_REAL_UE574_NANOS_DEPLOYMENTS";

static constexpr char TempHsMagic[] = "UEHS";
static constexpr char TempCtlMagic[] = "UECTL";

using TempCookie = std::array<uint8_t, 28>;

static uint64_t unix_seconds() { return (uint64_t)time(nullptr); }

static double monotonicish_seconds() {
  // Close enough for the first standalone prototype. UE uses driver elapsed
  // time for the timestamp; the client treats it as an opaque server value
  // which it echoes back.
  return (double)time(nullptr);
}

static void put_u64_be(uint8_t *p, uint64_t v) {
  for (int i = 0; i < 8; ++i) {
    p[7 - i] = (uint8_t)((v >> (i * 8)) & 0xff);
  }
}

static uint64_t get_u64_be(const uint8_t *p) {
  uint64_t v = 0;
  for (int i = 0; i < 8; ++i) {
    v = (v << 8) | p[i];
  }
  return v;
}

static void put_u32_le(uint8_t *p, uint32_t v) {
  p[0] = (uint8_t)(v);
  p[1] = (uint8_t)(v >> 8);
  p[2] = (uint8_t)(v >> 16);
  p[3] = (uint8_t)(v >> 24);
}

static TempCookie make_temp_cookie(const sockaddr_in &client, uint64_t ts) {
  TempCookie c{};
  put_u64_be(c.data(), ts);

  uint8_t msg[4 + 2 + 8];
  memcpy(msg + 0, &client.sin_addr.s_addr, 4);
  memcpy(msg + 4, &client.sin_port, 2);
  memcpy(msg + 6, c.data(), 8);

  auto mac = hmac_sha1(reinterpret_cast<const uint8_t *>(CookieSecret),
                       strlen(CookieSecret), msg, sizeof(msg));

  memcpy(c.data() + 8, mac.data(), mac.size());
  return c;
}

static std::array<uint8_t, CookieSize> make_ue_cookie(const sockaddr_in &client,
                                                      double timestamp) {
  // UE's real cookie is HMAC-SHA1 over serialized Timestamp + address string,
  // using a rotating server secret. The client treats the cookie as opaque and
  // echoes it. For this standalone endpoint, we need self-consistency, not the
  // engine's private secret representation.
  //
  // Store two little-endian sequence seeds in the first 4 bytes because UE's
  // client extracts initial packet sequence values from the cookie after Ack.
  uint8_t msg[4 + 2 + 8];
  memcpy(msg + 0, &client.sin_addr.s_addr, 4);
  memcpy(msg + 4, &client.sin_port, 2);
  memcpy(msg + 6, &timestamp, 8);

  auto mac = hmac_sha1(reinterpret_cast<const uint8_t *>(CookieSecret),
                       strlen(CookieSecret), msg, sizeof(msg));

  std::array<uint8_t, CookieSize> out{};
  memcpy(out.data(), mac.data(), out.size());

  // Keep these below MAX_PACKETID. The exact values are arbitrary for the PoC.
  put_u32_le(out.data(), 0x00420021u);
  return out;
}

const char *session_phase_name(SessionPhase p) {
  switch (p) {
  case SessionPhase::CookieValidated:
    return "CookieValidated";
  case SessionPhase::SawHello:
    return "SawHello";
  case SessionPhase::SawLogin:
    return "SawLogin";
  case SessionPhase::Welcomed:
    return "Welcomed";
  }
  return "?";
}

const char *packet_kind_name(PacketKind p) {
  switch (p) {
  case PacketKind::Unknown:
    return "Unknown";
  case PacketKind::TempHandshakeInitial:
    return "TempHandshakeInitial";
  case PacketKind::TempHandshakeResponse:
    return "TempHandshakeResponse";
  case PacketKind::TempControlHello:
    return "TempControlHello";
  case PacketKind::TempControlLogin:
    return "TempControlLogin";
  case PacketKind::UEHandshakeInitial:
    return "UEHandshakeInitial";
  case PacketKind::UEHandshakeResponse:
    return "UEHandshakeResponse";
  case PacketKind::UEHandshakeOther:
    return "UEHandshakeOther";
  case PacketKind::ProbablyUEPostHandshakeDatagram:
    return "ProbablyUEPostHandshakeDatagram";
  }
  return "?";
}

const char *handshake_type_name(uint8_t t) {
  switch (t) {
  case HandshakeTypeInitial:
    return "Initial";
  case HandshakeTypeChallenge:
    return "Challenge";
  case HandshakeTypeResponse:
    return "Response";
  case HandshakeTypeAck:
    return "Ack";
  case HandshakeTypeRestartHandshake:
    return "RestartHandshake";
  case HandshakeTypeRestartResponse:
    return "RestartResponse";
  case HandshakeTypeVersionUpgrade:
    return "VersionUpgrade";
  }
  return "Unknown";
}

static bool likely_valid_handshake_shape(const UEHandshake &h,
                                         uint32_t total_bits,
                                         uint32_t bits_left_after_parse) {
  if (!h.recognized)
    return false;

  if (h.remote_cur_version < HandshakeVersionRandomized ||
      h.remote_cur_version > HandshakeVersionLatest)
    return false;
  if (h.remote_min_version > h.remote_cur_version)
    return false;
  if (h.packet_type > HandshakeTypeVersionUpgrade)
    return false;

  // UE adds 8..16 bytes of random data plus a final termination bit. After
  // parsing the known handshake body, that should be the approximate residue.
  if (bits_left_after_parse < 65 || bits_left_after_parse > 129)
    return false;

  // Latest initial/response handshake packet total is normally:
  // 5 bits session/client + 1 handshake + 306 body bits + 64..128 random + 1
  // termination = 377..441 bits. Be permissive in case magic header is
  // configured later.
  if (total_bits < 300 || total_bits > 700)
    return false;

  return true;
}

UEHandshake try_parse_ue574_handshake(const uint8_t *data, size_t n) {
  UEHandshake h{};
  if (n == 0 || n > 4096)
    return h;

  BitReader br(data, n);

  uint64_t session = 0;
  uint64_t client = 0;
  bool is_handshake = false;

  if (!br.read_bits_u64(SessionIdBits, session))
    return h;
  if (!br.read_bits_u64(ClientIdBits, client))
    return h;
  if (!br.read_bit(is_handshake))
    return h;

  if (!is_handshake) {
    return h;
  }

  bool restart = false;
  if (!br.read_bit(restart))
    return h;

  uint8_t min_ver = 0, cur_ver = 0, packet_type = 0, sent_count = 0;
  if (!br.read_u8(min_ver))
    return h;
  if (!br.read_u8(cur_ver))
    return h;
  if (!br.read_u8(packet_type))
    return h;
  if (!br.read_u8(sent_count))
    return h;

  uint32_t net_version = 0;
  uint16_t net_features = 0;
  if (cur_ver >= HandshakeVersionNetCLVersion) {
    if (!br.read_u32(net_version))
      return h;
    if (!br.read_u16(net_features))
      return h;
  }

  h.recognized = true;
  h.session_id = (uint8_t)session;
  h.client_id = (uint8_t)client;
  h.restart = restart;
  h.remote_min_version = min_ver;
  h.remote_cur_version = cur_ver;
  h.packet_type = packet_type;
  h.remote_sent_count = sent_count;
  h.network_version = net_version;
  h.network_features = net_features;

  const bool has_cookie_body = packet_type == HandshakeTypeInitial ||
                               packet_type == HandshakeTypeChallenge ||
                               packet_type == HandshakeTypeResponse ||
                               packet_type == HandshakeTypeAck;

  if (has_cookie_body) {
    bool secret = false;
    if (!br.read_bit(secret)) {
      h.recognized = false;
      return h;
    }
    h.secret_id = secret ? 1 : 0;

    if (!br.read_double(h.timestamp)) {
      h.recognized = false;
      return h;
    }

    if (!br.read_bytes(h.cookie.data(), h.cookie.size())) {
      h.recognized = false;
      return h;
    }
  }

  if (!likely_valid_handshake_shape(h, (uint32_t)n * 8, br.bits_left())) {
    h.recognized = false;
  }

  return h;
}

ParsedPacket parse_datagram(const sockaddr_in &, const uint8_t *data,
                            size_t n) {
  ParsedPacket r{};

  if (n >= 5 && memcmp(data, TempHsMagic, 4) == 0) {
    if (data[4] == 1)
      r.kind = PacketKind::TempHandshakeInitial;
    else if (data[4] == 2)
      r.kind = PacketKind::TempHandshakeResponse;
    return r;
  }

  if (n >= 6 && memcmp(data, TempCtlMagic, 5) == 0) {
    if (data[5] == 1)
      r.kind = PacketKind::TempControlHello;
    else if (data[5] == 3)
      r.kind = PacketKind::TempControlLogin;
    return r;
  }

  r.handshake = try_parse_ue574_handshake(data, n);
  if (r.handshake.recognized) {
    if (r.handshake.packet_type == HandshakeTypeInitial &&
        r.handshake.timestamp == 0.0) {
      r.kind = PacketKind::UEHandshakeInitial;
    } else if (r.handshake.packet_type == HandshakeTypeResponse &&
               r.handshake.timestamp > 0.0) {
      r.kind = PacketKind::UEHandshakeResponse;
    } else {
      r.kind = PacketKind::UEHandshakeOther;
    }
    return r;
  }

  // After the stateless handler initializes, normal packets begin with the
  // same 5-bit session/client prefix and bHandshakePacket=0. Mark likely
  // binary packets so logs show the next implementation target.
  if (n >= 5) {
    bool mostly_printable = true;
    size_t check = n < 16 ? n : 16;
    for (size_t i = 0; i < check; ++i) {
      if (data[i] < 0x20 || data[i] > 0x7e) {
        mostly_printable = false;
        break;
      }
    }
    if (!mostly_printable)
      r.kind = PacketKind::ProbablyUEPostHandshakeDatagram;
  }

  return r;
}

static uint8_t choose_target_version(const UEHandshake &remote) {
  uint8_t v = remote.remote_cur_version;
  if (v > HandshakeVersionLatest)
    v = HandshakeVersionLatest;
  if (v < HandshakeVersionSessionClientId)
    v = HandshakeVersionSessionClientId;
  return v;
}

static void
begin_ue_handshake_packet(BitWriter &bw, uint8_t session_id, uint8_t client_id,
                          bool restart, uint8_t min_ver, uint8_t cur_ver,
                          uint8_t packet_type, uint8_t remote_sent_count,
                          uint32_t net_version, uint16_t net_features) {
  bw.write_bits_u64(session_id, SessionIdBits);
  bw.write_bits_u64(client_id, ClientIdBits);
  bw.write_bit(true);    // bHandshakePacket
  bw.write_bit(restart); // bRestartHandshake

  bw.write_u8(min_ver);
  bw.write_u8(cur_ver);
  bw.write_u8(packet_type);
  bw.write_u8(remote_sent_count);

  if (cur_ver >= HandshakeVersionNetCLVersion) {
    bw.write_u32(net_version);
    bw.write_u16(net_features);
  }
}

std::vector<uint8_t> build_ue574_initial(uint8_t client_id,
                                         uint32_t network_version,
                                         uint16_t network_features) {
  BitWriter bw;

  begin_ue_handshake_packet(bw, 0, client_id & 0x7, false,
                            HandshakeVersionSessionClientId,
                            HandshakeVersionLatest, HandshakeTypeInitial, 0,
                            network_version, network_features);

  bw.write_bit(false); // SecretIdPad
  uint8_t filler[28] = {};
  bw.write_bytes(filler, sizeof(filler));
  bw.write_random_bytes(8);
  bw.write_termination_bit();

  return bw.bytes();
}

std::vector<uint8_t> build_ue574_response(const UEHandshake &challenge) {
  BitWriter bw;

  const uint8_t target_version = choose_target_version(challenge);

  begin_ue_handshake_packet(
      bw, challenge.session_id & 0x3, challenge.client_id & 0x7, false,
      HandshakeVersionSessionClientId, target_version, HandshakeTypeResponse, 1,
      challenge.network_version, challenge.network_features);

  bw.write_bit(challenge.secret_id != 0);
  bw.write_double(challenge.timestamp);
  bw.write_bytes(challenge.cookie.data(), challenge.cookie.size());
  bw.write_random_bytes(8);
  bw.write_termination_bit();

  return bw.bytes();
}

std::vector<uint8_t> build_ue574_challenge(const sockaddr_in &to,
                                           const UEHandshake &initial) {
  BitWriter bw;

  const uint8_t target_version = choose_target_version(initial);
  const double ts = monotonicish_seconds();
  auto cookie = make_ue_cookie(to, ts);

  begin_ue_handshake_packet(
      bw,
      0, // CachedGlobalNetTravelCount low 2 bits. Use 0 for PoC.
      initial.client_id & 0x7, false, HandshakeVersionSessionClientId,
      target_version, HandshakeTypeChallenge, initial.remote_sent_count,
      initial.network_version, initial.network_features);

  bw.write_bit(false); // active secret id
  bw.write_double(ts);
  bw.write_bytes(cookie.data(), cookie.size());
  bw.write_random_bytes(8);
  bw.write_termination_bit();

  return bw.bytes();
}

bool validate_ue574_response(const sockaddr_in &from,
                             const UEHandshake &response) {
  if (!response.recognized)
    return false;
  if (response.packet_type != HandshakeTypeResponse)
    return false;
  if (response.timestamp <= 0.0)
    return false;

  double now = monotonicish_seconds();
  if (response.timestamp > now + 2.0)
    return false;
  if ((now - response.timestamp) > (double)UECookieTtlSeconds)
    return false;

  auto expected = make_ue_cookie(from, response.timestamp);
  return constant_time_eq(response.cookie.data(), expected.data(),
                          expected.size());
}

std::vector<uint8_t> build_ue574_ack(const UEHandshake &response) {
  BitWriter bw;

  const uint8_t target_version = choose_target_version(response);

  begin_ue_handshake_packet(
      bw, 0, response.client_id & 0x7, false, HandshakeVersionSessionClientId,
      target_version, HandshakeTypeAck, response.remote_sent_count,
      response.network_version, response.network_features);

  bw.write_bit(true);    // ActiveSecret_Unused in UE source
  bw.write_double(-1.0); // negative timestamp marks ack
  bw.write_bytes(response.cookie.data(), response.cookie.size());
  bw.write_random_bytes(8);
  bw.write_termination_bit();

  return bw.bytes();
}

// Temporary harness remains useful for smoke-testing the server without UE.
std::vector<uint8_t> build_temp_handshake_challenge(const sockaddr_in &to) {
  TempCookie c = make_temp_cookie(to, unix_seconds());

  std::vector<uint8_t> out;
  out.insert(out.end(), TempHsMagic, TempHsMagic + 4);
  out.push_back(0x81);
  out.insert(out.end(), c.begin(), c.end());
  return out;
}

bool validate_temp_handshake_response(const sockaddr_in &from,
                                      const uint8_t *data, size_t n) {
  if (n != 5 + 28)
    return false;
  if (memcmp(data, TempHsMagic, 4) != 0 || data[4] != 2)
    return false;

  const uint8_t *cookie = data + 5;
  uint64_t ts = get_u64_be(cookie);
  uint64_t now = unix_seconds();

  if (ts > now + 2)
    return false;
  if (now - ts > TempCookieTtlSeconds)
    return false;

  TempCookie expected = make_temp_cookie(from, ts);
  return constant_time_eq(cookie, expected.data(), expected.size());
}

std::vector<uint8_t> build_temp_handshake_ok() {
  return {'U', 'E', 'H', 'S', 0x82};
}

std::vector<uint8_t> build_temp_control_challenge() {
  return {'U', 'E', 'C', 'T', 'L', 0x82};
}

std::vector<uint8_t> build_temp_welcome() {
  const char payload[] = "UECTL\x84"
                         "Target=UE5.7.4\n"
                         "Message=Fake NMT_Welcome placeholder\n"
                         "Map=/Game/Maps/Minimal\n"
                         "Game=/Script/Engine.GameModeBase\n";

  return std::vector<uint8_t>(reinterpret_cast<const uint8_t *>(payload),
                              reinterpret_cast<const uint8_t *>(payload) +
                                  sizeof(payload) - 1);
}

} // namespace ue574
