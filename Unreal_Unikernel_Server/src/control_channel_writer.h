#pragma once

#include "ue57_protocol.h"

#include <stdint.h>
#include <string>
#include <vector>

namespace ue574 {

enum class ActorChannelNameWireMode : uint8_t {
  // UE5.7.4 captures/probes show that this client's PacketEngineNetVer still
  // follows the pre-ChannelNames branch for non-control actor-channel opens,
  // so the useful actor probe is the legacy EChannelType value CHTYPE_Actor=2.
  // Keep the string form as an A/B probe because control-channel reliable
  // bunches are accepted with StaticSerializeName string fallback.
  LegacyChannelTypeActor = 0,
  StaticSerializeNameStringActor = 1,
};

enum class ActorPayloadProbeMode : uint8_t {
  // v37 proved the legacy actor-channel header is ACKed and not rejected as
  // BunchWrongChannelType. These payload modes deliberately exercise the next
  // layer: UPackageMapClient::SerializeNewActor. They are probes, not real
  // PlayerController/Pawn replication yet.
  Empty = 0,
  ZeroByte = 1,
  FourZeroBytes = 2,

  // v39 probes: start sending fields that look like the beginning of
  // UPackageMapClient::SerializeNewActor / SerializeObject data. These are
  // intentionally tiny and diagnostic. They do not export paths or create a
  // valid PlayerController/Pawn yet, but they should move failures away from
  // empty-payload timeout pressure and toward NetGUID / object-resolution
  // errors if the expected field boundary is right.
  PackedNetGuidZero = 3,
  PackedNetGuidOne = 4,
  PackedNetGuidOneClassZero = 5,
  PackedNetGuidOneClassOne = 6,

  // v41 probes: FNetworkGUID's low bit is the static flag (see UE debug
  // FindNetGUID helper: NetIndex = GUIDValue >> 1, bStatic = GUIDValue & 1).
  // Spawned replicated actors should use dynamic, non-default GUID values, so
  // probe even values such as 2 instead of only odd/static value 1.
  DynamicActorGuid2 = 7,
  DynamicActorGuid2Class0 = 8,
  DynamicActorGuid2Class1 = 9,
  DynamicActorGuid2Class3 = 10,
  DynamicActorGuid2ContentEmpty = 11,

  // v42 probes: exercise the bHasMustBeMappedGUIDs prefix that UE prepends
  // before actor bunch payload when references must resolve before processing.
  // This is still intentionally diagnostic: no PackageMap export is sent, so
  // a clean UnregisteredMustBeMappedGUID/actor pressure outcome tells us the
  // client reached the pre-SerializeNewActor must-map boundary.
  MustMapNoneThenGuid2 = 12,
  MustMapGuid2ThenGuid2 = 13,
  MustMapGuid2Guid4ThenGuid2 = 14,

  // v43 probes: flip bHasPackageMapExports and place an intentionally small
  // export-like prefix before the SerializeNewActor actor GUID. These are
  // still diagnostic, but they test the next likely boundary: PackageMap
  // export/path registration before actor GUID resolution.
  ExportCount0ThenGuid2 = 15,
  ExportGuid2ActorPathThenGuid2 = 16,
  ExportGuid2ClassPathThenGuid2 = 17,
};

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

// PacketNotify-only packet: no reliable bunch, just ACK the latest client
// packet. Needed after Welcome so the client's NetSpeed/Join-side reliable
// traffic stops being retransmitted while we have no real game-state packets
// yet.
std::vector<uint8_t>
build_experimental_ack_only_packet(const UEHandshake &response,
                                   uint16_t last_client_packet_seq,
                                   uint16_t next_server_packet_seq);
std::vector<uint8_t> build_experimental_empty_actor_channel_open_probe(
    const UEHandshake &response, uint16_t last_client_packet_seq,
    uint16_t next_server_packet_seq, uint16_t actor_channel_index,
    uint16_t next_out_reliable_actor_ch,
    ActorChannelNameWireMode actor_name_mode,
    ActorPayloadProbeMode payload_mode = ActorPayloadProbeMode::Empty,
    const std::string &actor_class_path_hint = std::string());

const char *actor_channel_name_wire_mode_name(ActorChannelNameWireMode mode);
const char *actor_payload_probe_mode_name(ActorPayloadProbeMode mode);

std::vector<uint8_t>
build_experimental_nmt_challenge(const UEHandshake &response,
                                 uint16_t last_client_packet_seq);
std::vector<uint8_t>
build_experimental_nmt_welcome(const UEHandshake &response,
                               uint16_t last_client_packet_seq);

// Stateful variants: required once we send more than one reliable control
// bunch. Each outgoing packet must advance PacketNotify sequence and each
// reliable channel-0 bunch must advance ChSequence; reusing the same values
// makes the UE client treat later replies as duplicates/out-of-window packets.
std::vector<uint8_t> build_experimental_nmt_challenge_stateful(
    const UEHandshake &response, uint16_t last_client_packet_seq,
    uint16_t next_server_packet_seq, uint16_t next_out_reliable_ch0);
std::vector<uint8_t> build_experimental_nmt_welcome_stateful(
    const UEHandshake &response, uint16_t last_client_packet_seq,
    uint16_t next_server_packet_seq, uint16_t next_out_reliable_ch0);

std::vector<uint8_t> build_experimental_nmt_welcome_stateful_custom(
    const UEHandshake &response, uint16_t last_client_packet_seq,
    uint16_t next_server_packet_seq, uint16_t next_out_reliable_ch0,
    const std::string &level_name, const std::string &game_name,
    const std::string &redirect_url);

// Diagnostic post-Welcome control reply. If the stock client displays this
// failure message or disconnects cleanly, it proves post-Welcome reliable
// server->client control bunches are accepted and sequenced correctly.
std::vector<uint8_t> build_experimental_nmt_failure_stateful_custom(
    const UEHandshake &response, uint16_t last_client_packet_seq,
    uint16_t next_server_packet_seq, uint16_t next_out_reliable_ch0,
    const std::string &failure_text);

// Older candidate builders kept for A/B testing if needed, but the endpoint now
// sends one clean candidate by default.
std::vector<std::vector<uint8_t>>
build_experimental_nmt_challenge_candidates(const UEHandshake &response,
                                            uint16_t last_client_packet_seq);
std::vector<std::vector<uint8_t>>
build_experimental_nmt_welcome_candidates(const UEHandshake &response,
                                          uint16_t last_client_packet_seq);

const char *name_wire_mode_name(NameWireMode mode);

} // namespace ue574
