#include "control_channel_probe.h"
#include "bit_io.h"

#include <stdio.h>

namespace ue574 {

const char *control_message_name(uint8_t id) {
  switch (id) {
  case NMT_Hello:
    return "NMT_Hello";
  case NMT_Welcome:
    return "NMT_Welcome";
  case NMT_Upgrade:
    return "NMT_Upgrade";
  case NMT_Challenge:
    return "NMT_Challenge";
  case NMT_Netspeed:
    return "NMT_Netspeed";
  case NMT_Login:
    return "NMT_Login";
  case NMT_Failure:
    return "NMT_Failure";
  case NMT_Join:
    return "NMT_Join";
  default:
    return "unknown/other";
  }
}

static uint32_t ceil_log2_u32(uint32_t max_value) {
  // UE ReadInt(Max) needs enough bits to represent Max-1.
  uint32_t v = max_value > 0 ? max_value - 1 : 0;
  uint32_t bits = 0;
  while (v > 0) {
    ++bits;
    v >>= 1;
  }
  return bits;
}

static bool read_int_wrapped_safe(BitReader &r, uint32_t max_value,
                                  uint32_t &out) {
  uint64_t tmp = 0;
  if (!r.read_bits_u64(ceil_log2_u32(max_value), tmp))
    return false;
  out = (uint32_t)tmp;
  return true;
}

static bool read_int_packed_approx(BitReader &r, uint32_t &out) {
  // FArchive::SerializeIntPacked-style LEB128-ish reader: 7 data bits plus a
  // continuation bit per byte. This is correct for zero and small channel ids,
  // which is all the control channel needs for the first pass.
  out = 0;
  uint32_t shift = 0;

  for (int group = 0; group < 5; ++group) {
    uint64_t low7 = 0;
    if (!r.read_bits_u64(7, low7))
      return false;

    bool more = false;
    if (!r.read_bit(more))
      return false;

    out |= (uint32_t)(low7 << shift);
    if (!more)
      return true;
    shift += 7;
  }

  return false;
}

static bool peek_payload_first_byte(const uint8_t *data, size_t n,
                                    uint32_t bit_pos, uint8_t &out) {
  BitReader r(data, n);
  uint64_t throwaway = 0;
  if (bit_pos > 0 && !r.read_bits_u64(bit_pos, throwaway))
    return false;
  return r.read_u8(out);
}

static uint32_t ue_payload_bit_count(const uint8_t *data, size_t n,
                                     bool &has_term) {
  has_term = false;
  if (n == 0)
    return 0;

  uint8_t last = data[n - 1];
  if (last == 0)
    return (uint32_t)n * 8;

  uint32_t bit_size = (uint32_t)n * 8 - 1;
  has_term = true;

  // Mirrors UNetConnection::ReceivedRawPacket termination-bit stripping:
  // walk backward through zero high bits in the final byte until the set bit.
  while ((last & 0x80u) == 0) {
    last <<= 1;
    --bit_size;
  }

  return bit_size;
}

static BunchProbe try_parse_bunch_at(const uint8_t *data, size_t n,
                                     uint32_t start_bit,
                                     uint32_t payload_bits) {
  BunchProbe p{};
  p.start_bit = start_bit;

  if (start_bit >= payload_bits) {
    p.reason = "start beyond payload";
    return p;
  }

  BitReader r(data, n);
  uint64_t skip = 0;
  if (start_bit > 0 && !r.read_bits_u64(start_bit, skip)) {
    p.reason = "cannot skip";
    return p;
  }

  bool b = false;
  if (!r.read_bit(p.control)) {
    p.reason = "no control bit";
    return p;
  }
  if (p.control) {
    if (!r.read_bit(p.open)) {
      p.reason = "no open bit";
      return p;
    }
    if (!r.read_bit(p.close)) {
      p.reason = "no close bit";
      return p;
    }
    if (p.close) {
      uint64_t close_reason = 0;
      // EChannelCloseReason::MAX 
      // Skip a small field; early hello should not be close anyway.
      if (!r.read_bits_u64(4, close_reason)) {
        p.reason = "no close reason";
        return p;
      }
    }
  }

  bool replication_paused = false;
  if (!r.read_bit(replication_paused)) {
    p.reason = "no pause bit";
    return p;
  }
  if (!r.read_bit(p.reliable)) {
    p.reason = "no reliable bit";
    return p;
  }

  if (!read_int_packed_approx(r, p.channel_index)) {
    p.reason = "bad packed channel index";
    return p;
  }

  bool has_exports = false;
  bool has_must_map = false;
  if (!r.read_bit(has_exports)) {
    p.reason = "no exports bit";
    return p;
  }
  if (!r.read_bit(has_must_map)) {
    p.reason = "no must-map bit";
    return p;
  }
  if (!r.read_bit(p.partial)) {
    p.reason = "no partial bit";
    return p;
  }

  if (p.reliable) {
    if (!read_int_wrapped_safe(r, 1024, p.channel_sequence)) {
      p.reason = "bad channel sequence";
      return p;
    }
  }

  if (p.partial) {
    bool dummy = false;
    if (!r.read_bit(dummy)) {
      p.reason = "no partial initial";
      return p;
    }
    if (!r.read_bit(dummy)) {
      p.reason = "no partial custom final";
      return p;
    }
    if (!r.read_bit(dummy)) {
      p.reason = "no partial final";
      return p;
    }
  }

  // If bOpen or bReliable, UE serializes ChName here. For the first client
  // hello, this is usually channel 0/control. We do not know the exact FName
  // wire form yet, so this probe searches forward for
  // a plausible first control-message byte 
  const uint32_t after_known_header = r.pos_bits();
  const uint32_t max_scan_bits = after_known_header + 96;
  for (uint32_t bit = after_known_header;
       bit + 8 <= payload_bits && bit <= max_scan_bits; ++bit) {
    uint8_t first = 0xff;
    if (!peek_payload_first_byte(data, n, bit, first))
      break;
    if (first <= 32) {
      p.first_payload_byte = first;
      p.header_bits = bit - start_bit;
      p.data_bits = payload_bits - bit;
      p.plausible = (p.channel_index == 0) &&
                    (first == NMT_Hello || first == NMT_Login ||
                     first == NMT_Netspeed || first == NMT_Join);
      p.reason = p.plausible ? "found plausible control message byte"
                             : "found low message-like byte";
      return p;
    }
  }

  p.reason = "no plausible control message byte found after bunch header";
  return p;
}

PostHandshakeProbeReport probe_post_handshake_packet(const uint8_t *data,
                                                     size_t n) {
  PostHandshakeProbeReport report{};
  report.payload_bits =
      ue_payload_bit_count(data, n, report.has_ue_termination);

  for (uint32_t off = 0; off < 160 && off + 24 < report.payload_bits; ++off) {
    BunchProbe p = try_parse_bunch_at(data, n, off, report.payload_bits);
    if (p.plausible || (p.channel_index == 0 && p.first_payload_byte != 0xff)) {
      report.candidates.push_back(p);
      if (report.candidates.size() >= 8)
        break;
    }
  }

  return report;
}

std::string
format_post_handshake_report(const PostHandshakeProbeReport &report) {
  char buf[512];
  std::string out;
  snprintf(buf, sizeof(buf),
           "  UE packet probe: payload_bits=%u termination=%s candidates=%zu\n",
           report.payload_bits, report.has_ue_termination ? "yes" : "no",
           report.candidates.size());
  out += buf;

  for (const BunchProbe &p : report.candidates) {
    snprintf(buf, sizeof(buf),
             "    candidate: start_bit=%u header_bits=%u data_bits=%u "
             "control=%u open=%u close=%u reliable=%u partial=%u ch=%u seq=%u "
             "first=0x%02x(%s) %s\n",
             p.start_bit, p.header_bits, p.data_bits, p.control ? 1u : 0u,
             p.open ? 1u : 0u, p.close ? 1u : 0u, p.reliable ? 1u : 0u,
             p.partial ? 1u : 0u, p.channel_index, p.channel_sequence,
             p.first_payload_byte, control_message_name(p.first_payload_byte),
             p.reason.c_str());
    out += buf;
  }

  if (report.candidates.empty()) {
    out += "    no candidate control bunch found; save binlog/pcap and compare "
           "packet header bits\n";
  }

  return out;
}

} // namespace ue574
