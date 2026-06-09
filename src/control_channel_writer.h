#pragma once

#include "ue57_protocol.h"

#include <netinet/in.h>
#include <stdint.h>
#include <string>
#include <vector>

namespace ue574 {

enum class NameWireMode : uint8_t {
  // CoreNet.cpp confirms UPackageMap::StaticSerializeName writes either:
  //   bit 1 + packed hardcoded EName index
  // or:
  //   bit 0 + FString plain name + int32 name number.
  //
  // We use the string fallback because it is accepted by the load path and
  // does not require knowing the engine's numeric EName::Control index.
  StaticSerializeNameStringControl = 0,

  // Kept only as optional probes while testing against a real client.
  SmallHardcodedIndexProbe = 1,
  LegacyChannelTypeControlProbe = 2,
};

struct PacketNotifyHeaderMini {
  bool ok = false;
  uint16_t seq = 0;
  uint16_t acked_seq = 0;
  uint8_t history_word_count = 0;
  uint32_t bits_consumed = 0;
};

struct ControlReplyBuildInput {
  uint8_t session_id = 0;
  uint8_t client_id = 0;
  uint16_t server_sequence = 0;
  uint16_t client_sequence = 0;
  uint16_t last_client_packet_seq = 0;
  uint16_t next_server_packet_seq = 0;
  uint16_t next_out_reliable_ch0 = 0;
  uint8_t message_id = 0;
  std::string message_text;
  std::vector<std::string> message_strings;
  NameWireMode name_mode = NameWireMode::StaticSerializeNameStringControl;
};

PacketNotifyHeaderMini
parse_packet_notify_after_stateless_prefix(const uint8_t *data, size_t n);
void extract_sequences_from_cookie(const UEHandshake &response,
                                   uint16_t &server_sequence,
                                   uint16_t &client_sequence);

std::vector<uint8_t>
build_experimental_control_reply_packet(const ControlReplyBuildInput &in);
std::vector<std::vector<uint8_t>>
build_experimental_nmt_challenge_candidates(const UEHandshake &response,
                                            uint16_t last_client_packet_seq);
std::vector<std::vector<uint8_t>>
build_experimental_nmt_welcome_candidates(const UEHandshake &response,
                                          uint16_t last_client_packet_seq);

const char *name_wire_mode_name(NameWireMode mode);

} // namespace ue574
