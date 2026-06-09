#include "ue57_protocol.h"
#include "crypto_sha1_hmac.h"

#include <string.h>
#include <time.h>

namespace ue574 {

static constexpr uint32_t CookieTtlSeconds = 20;
static constexpr char CookieSecret[] =
    "CHANGE_ME_FOR_REAL_UE574_NANOS_DEPLOYMENTS";

static constexpr char TempHsMagic[] = "UEHS";
static constexpr char TempCtlMagic[] = "UECTL";

using Cookie = std::array<uint8_t, 28>;

static uint64_t unix_seconds() { return (uint64_t)time(nullptr); }

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

static Cookie make_temp_cookie(const sockaddr_in &client, uint64_t ts) {
  Cookie c{};
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

const char *session_phase_name(SessionPhase p) {
  switch (p) {
  case SessionPhase::CookieValidated:
    return "CookieValidated";
  case SessionPhase::SawHello:
    return "SawHello";
  case SessionPhase::Welcomed:
    return "Welcomed";
  }
  return "?";
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

  UE574DecodeResult ue = try_decode_ue574_packet(data, n);
  if (ue.recognized) {
    r.kind = PacketKind::ProbablyUEPacketHandlerDatagram;
  }

  return r;
}

std::vector<uint8_t> build_temp_handshake_challenge(const sockaddr_in &to) {
  Cookie c = make_temp_cookie(to, unix_seconds());

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
  if (now - ts > CookieTtlSeconds)
    return false;

  Cookie expected = make_temp_cookie(from, ts);
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

UE574DecodeResult try_decode_ue574_packet(const uint8_t *data, size_t n) {
  UE574DecodeResult r{};

  // Conservative heuristic only:
  // UE PacketHandler traffic is bit-packed and will not carry the temp ASCII
  // magic. For now, flag nonempty UDP payloads that are plausible sizes so
  // captures are easy to spot in logs.
  //
  // Replace this function with real 5.7.4 parsing.
  if (n >= 5 && n <= 2048) {
    // Avoid claiming random printable test packets are UE.
    bool mostly_printable = true;
    size_t check = n < 16 ? n : 16;
    for (size_t i = 0; i < check; ++i) {
      if (data[i] < 0x20 || data[i] > 0x7e) {
        mostly_printable = false;
        break;
      }
    }

    if (!mostly_printable) {
      r.recognized = true;
    }
  }

  return r;
}

} // namespace ue574
