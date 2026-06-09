#include "control_channel_writer.h"
#include "bit_io.h"
#include "control_channel_probe.h"

#include <string.h>

namespace ue574 {

static constexpr uint32_t PacketNotifySeqBits = 14;
static constexpr uint32_t PacketNotifyHistoryWordCountBits = 4;
static constexpr uint32_t MaxPacketId = 1u << PacketNotifySeqBits;
static constexpr uint32_t MaxChSequence = 1024;

const char *name_wire_mode_name(NameWireMode mode) {
  switch (mode) {
  case NameWireMode::OmitName:
    return "omit-name";
  case NameWireMode::SmallHardcodedIndex:
    return "small-hardcoded-index";
  case NameWireMode::AnsiString:
    return "ansi-string";
  case NameWireMode::LegacyChannelTypeControl:
    return "legacy-channel-type-control";
  }
  return "?";
}

void extract_sequences_from_cookie(const UEHandshake &response,
                                   uint16_t &server_sequence,
                                   uint16_t &client_sequence) {
  // UE extracts two int16 values from the first four cookie bytes, masked by
  // MAX_PACKETID-1.
  uint16_t a =
      (uint16_t)(response.cookie[0] | (uint16_t(response.cookie[1]) << 8));
  uint16_t b =
      (uint16_t)(response.cookie[2] | (uint16_t(response.cookie[3]) << 8));
  server_sequence = (uint16_t)(a & (MaxPacketId - 1));
  client_sequence = (uint16_t)(b & (MaxPacketId - 1));
}

PacketNotifyHeaderMini
parse_packet_notify_after_stateless_prefix(const uint8_t *data, size_t n) {
  PacketNotifyHeaderMini out{};
  BitReader r(data, n);

  uint64_t session = 0, client = 0;
  bool handshake = false;
  if (!r.read_bits_u64(SessionIdBits, session))
    return out;
  if (!r.read_bits_u64(ClientIdBits, client))
    return out;
  if (!r.read_bit(handshake))
    return out;
  if (handshake)
    return out;

  uint32_t packed = 0;
  if (!r.read_u32(packed))
    return out;

  const uint32_t history_words_minus_one =
      packed & ((1u << PacketNotifyHistoryWordCountBits) - 1u);
  const uint32_t ack_shift = PacketNotifyHistoryWordCountBits;
  const uint32_t seq_shift = ack_shift + PacketNotifySeqBits;

  out.seq = (uint16_t)((packed >> seq_shift) & (MaxPacketId - 1));
  out.acked_seq = (uint16_t)((packed >> ack_shift) & (MaxPacketId - 1));
  out.history_word_count = (uint8_t)(history_words_minus_one + 1);

  // Consume the ack history words. TSequenceHistory uses 32-bit words.
  for (uint8_t i = 0; i < out.history_word_count; ++i) {
    uint32_t word = 0;
    if (!r.read_u32(word))
      return PacketNotifyHeaderMini{};
  }

  out.bits_consumed = r.pos_bits();
  out.ok = true;
  return out;
}

static void write_packet_notify_header(BitWriter &w, uint16_t seq,
                                       uint16_t acked_seq) {
  // FNetPacketNotify::WriteHeader packs:
  //   seq:14 | acked:14 | history_words_minus_one:4
  // and always writes at least one history word.
  uint32_t packed = 0;
  packed |= (uint32_t(seq) & (MaxPacketId - 1))
            << (PacketNotifyHistoryWordCountBits + PacketNotifySeqBits);
  packed |= (uint32_t(acked_seq) & (MaxPacketId - 1))
            << PacketNotifyHistoryWordCountBits;
  packed |= 0; // one history word => count-minus-one 0
  w.write_u32(packed);
  w.write_u32(
      0); // empty/synthetic ack history word for the first experimental reply
}

static void write_fname_control_placeholder(BitWriter &w, NameWireMode mode) {
  // TODO: replace with UPackageMap::StaticSerializeName(NAME_Control).
  // These modes are only candidate probes. They deliberately keep all name
  // serialization in one place so the real implementation can replace it.
  switch (mode) {
  case NameWireMode::OmitName:
    return;
  case NameWireMode::SmallHardcodedIndex:
    // Candidate shape: small non-string integer id. The value is not
    // asserted to be correct; it is useful for packet experiments only.
    w.write_bit(true);     // candidate: is hardcoded/integer
    w.write_int_packed(0); // candidate id placeholder
    return;
  case NameWireMode::AnsiString: {
    // Candidate shape for the fallback path in StaticSerializeName: an
    // archive string-ish representation of FName("Control"). This is
    // intentionally still a probe, not an assertion of the final format.
    const char name[] = "Control";
    w.write_u32(sizeof(name));
    w.write_bytes(reinterpret_cast<const uint8_t *>(name), sizeof(name));
    return;
  }
  case NameWireMode::LegacyChannelTypeControl:
    // Pre-ChannelNames path in UNetConnection::ReceivedPacket reads
    // Reader.ReadInt(CHTYPE_MAX), with CHTYPE_Control == 1 and
    // CHTYPE_MAX == 8, so this is three LSB-first bits: 001. Modern
    // 5.7.4 should normally use StaticSerializeName instead, but keeping
    // this candidate is useful if the early connection has not negotiated
    // channel-name serialization as expected.
    w.write_int_wrapped(1, 8);
    return;
  }
}

static void write_i32(BitWriter &w, int32_t v) { w.write_u32((uint32_t)v); }

static void write_ue_fstring_ansi(BitWriter &w, const std::string &text) {
  // UE FString serialization for a plain non-wide string is a signed int32
  // character count, including the NUL terminator, followed by ANSI bytes.
  // Negative counts indicate wide/TCHAR data. We only need ASCII challenge,
  // URL/map/game strings for this prototype.
  write_i32(w, (int32_t)text.size() + 1);
  if (!text.empty()) {
    w.write_bytes(reinterpret_cast<const uint8_t *>(text.data()), text.size());
  }
  w.write_u8(0);
}

static void write_control_payload_string_approx(BitWriter &w, uint8_t msg_id,
                                                const std::string &text) {
  w.write_u8(msg_id);
  write_ue_fstring_ansi(w, text);
}

std::vector<uint8_t>
build_experimental_control_reply_packet(const ControlReplyBuildInput &in) {
  BitWriter normal;

  const uint16_t packet_seq = in.next_server_packet_seq
                                  ? in.next_server_packet_seq
                                  : in.server_sequence;
  const uint16_t ack_seq = in.last_client_packet_seq ? in.last_client_packet_seq
                                                     : in.client_sequence;
  write_packet_notify_header(normal, packet_seq, ack_seq);

  BitWriter bunch_payload;
  write_control_payload_string_approx(bunch_payload, in.message_id,
                                      in.message_text);

  // UNetConnection::SendRawBunch header for reliable channel-0 control bunch.
  normal.write_bit(false);    // bIsOpenOrClose
  normal.write_bit(false);    // bIsReplicationPaused
  normal.write_bit(true);     // bReliable
  normal.write_int_packed(0); // ChIndex 0
  normal.write_bit(false);    // bHasPackageMapExports
  normal.write_bit(false);    // bHasMustBeMappedGUIDs
  normal.write_bit(false);    // bPartial
  normal.write_int_wrapped(in.next_out_reliable_ch0 & (MaxChSequence - 1),
                           MaxChSequence);
  write_fname_control_placeholder(normal, in.name_mode);
  normal.write_int_wrapped(bunch_payload.bit_count(),
                           1024 * 8); // MaxPacket-ish bound for prototype
  normal.append_bits(bunch_payload);

  normal.write_termination_bit(); // UNetConnection termination bit before
                                  // PacketHandler outgoing

  BitWriter out;
  out.write_bits_u64(in.session_id & 0x3, SessionIdBits);
  out.write_bits_u64(in.client_id & 0x7, ClientIdBits);
  out.write_bit(false); // bHandshakePacket=0
  out.append_bits(normal);
  return out.bytes();
}

static ControlReplyBuildInput base_input(const UEHandshake &response,
                                         uint16_t last_client_packet_seq) {
  uint16_t server_seq = 0, client_seq = 0;
  extract_sequences_from_cookie(response, server_seq, client_seq);

  ControlReplyBuildInput in{};
  in.session_id = 0;
  in.client_id = response.client_id;
  in.server_sequence = server_seq;
  in.client_sequence = client_seq;
  in.last_client_packet_seq =
      last_client_packet_seq ? last_client_packet_seq : client_seq;
  in.next_server_packet_seq = server_seq;
  in.next_out_reliable_ch0 =
      (uint16_t)(((server_seq & (MaxChSequence - 1)) + 1) &
                 (MaxChSequence - 1));
  return in;
}

std::vector<std::vector<uint8_t>>
build_experimental_nmt_challenge_candidates(const UEHandshake &response,
                                            uint16_t last_client_packet_seq) {
  std::vector<std::vector<uint8_t>> out;
  for (NameWireMode mode :
       {NameWireMode::OmitName, NameWireMode::SmallHardcodedIndex,
        NameWireMode::AnsiString, NameWireMode::LegacyChannelTypeControl}) {
    auto in = base_input(response, last_client_packet_seq);
    in.message_id = NMT_Challenge;
    in.message_text = "00000000";
    in.name_mode = mode;
    out.push_back(build_experimental_control_reply_packet(in));
  }
  return out;
}

std::vector<std::vector<uint8_t>>
build_experimental_nmt_welcome_candidates(const UEHandshake &response,
                                          uint16_t last_client_packet_seq) {
  std::vector<std::vector<uint8_t>> out;
  for (NameWireMode mode :
       {NameWireMode::OmitName, NameWireMode::SmallHardcodedIndex,
        NameWireMode::AnsiString, NameWireMode::LegacyChannelTypeControl}) {
    auto in = base_input(response, last_client_packet_seq);
    in.message_id = NMT_Welcome;
    in.message_text = "/Game/Maps/Minimal?game=/Script/Engine.GameModeBase";
    in.name_mode = mode;
    out.push_back(build_experimental_control_reply_packet(in));
  }
  return out;
}

} // namespace ue574
