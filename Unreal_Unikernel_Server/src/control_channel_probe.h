#pragma once

#include <stddef.h>
#include <stdint.h>
#include <string>
#include <vector>

namespace ue574 {

// Known early control messages. Values are from the conventional UE control
// channel order; the probe treats them as hints, not proof, until bunch framing
// is fully decoded from the target build.
enum ControlMessageId : uint8_t {
  NMT_Hello = 0,
  NMT_Welcome = 1,
  NMT_Upgrade = 2,
  NMT_Challenge = 3,
  NMT_Netspeed = 4,
  NMT_Login = 5,
  NMT_Failure = 6,
  // UE5.7.4 DataChannel.h: DEFINE_CONTROL_CHANNEL_MESSAGE(ActorChannelFailure,
  // 16, int32).
  NMT_ActorChannelFailure = 16,
  // UE5.7.4 DataChannel.h: DEFINE_CONTROL_CHANNEL_MESSAGE(Join, 9).
  // Earlier scaffolds used 7 as a placeholder, which made true 0x09 join
  // bytes appear as "unknown/other".
  NMT_Join = 9,
};

const char *control_message_name(uint8_t id);

struct BunchProbe {
  bool plausible = false;
  uint32_t start_bit = 0;
  uint32_t header_bits = 0;
  uint32_t data_bits = 0;

  bool control = false;
  bool open = false;
  bool close = false;
  bool reliable = false;
  bool partial = false;
  uint32_t channel_index = 0;
  uint32_t channel_sequence = 0;
  uint8_t first_payload_byte = 0xff;
  std::string reason;
};

struct PostHandshakeProbeReport {
  bool has_ue_termination = false;
  uint32_t payload_bits = 0;
  std::vector<BunchProbe> candidates;
};

PostHandshakeProbeReport probe_post_handshake_packet(const uint8_t *data,
                                                     size_t n);
// Parse exactly one bunch starting at an already-known bit offset, e.g. after
// StatelessConnect + PacketNotify + packet-info. This avoids the broad scanner
// false positives used during early reverse engineering.
PostHandshakeProbeReport
probe_post_handshake_packet_from_bit(const uint8_t *data, size_t n,
                                     uint32_t start_bit);
std::string
format_post_handshake_report(const PostHandshakeProbeReport &report);

} // namespace ue574
