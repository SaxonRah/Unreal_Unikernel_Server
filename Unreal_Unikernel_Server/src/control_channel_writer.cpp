#include "control_channel_writer.h"
#include "bit_io.h"
#include "control_channel_probe.h"

#include <string.h>

namespace ue574 {

static constexpr uint32_t PacketNotifySeqBits = 14;
static constexpr uint32_t PacketNotifyHistoryWordCountBits = 4;
static constexpr uint32_t MaxPacketId = 1u << PacketNotifySeqBits;
static constexpr uint32_t MaxChSequence = 1024;
static constexpr uint32_t NumBitsForJitterClockTimeInHeader = 10;
static constexpr uint32_t MaxJitterClockTimeValue =
    (1u << NumBitsForJitterClockTimeInHeader) - 1u;

const char *actor_channel_name_wire_mode_name(ActorChannelNameWireMode mode) {
  switch (mode) {
  case ActorChannelNameWireMode::LegacyChannelTypeActor:
    return "legacy-CHTYPE_Actor";
  case ActorChannelNameWireMode::StaticSerializeNameStringActor:
    return "static-serialize-name-string-Actor";
  }
  return "?";
}

const char *actor_payload_probe_mode_name(ActorPayloadProbeMode mode) {
  switch (mode) {
  case ActorPayloadProbeMode::Empty:
    return "empty";
  case ActorPayloadProbeMode::ZeroByte:
    return "zero8";
  case ActorPayloadProbeMode::FourZeroBytes:
    return "zero32";
  case ActorPayloadProbeMode::PackedNetGuidZero:
    return "netguid0";
  case ActorPayloadProbeMode::PackedNetGuidOne:
    return "netguid1";
  case ActorPayloadProbeMode::PackedNetGuidOneClassZero:
    return "netguid1-class0";
  case ActorPayloadProbeMode::PackedNetGuidOneClassOne:
    return "netguid1-class1";
  case ActorPayloadProbeMode::DynamicActorGuid2:
    return "dynamic-guid2";
  case ActorPayloadProbeMode::DynamicActorGuid2Class0:
    return "dynamic-guid2-class0";
  case ActorPayloadProbeMode::DynamicActorGuid2Class1:
    return "dynamic-guid2-class1";
  case ActorPayloadProbeMode::DynamicActorGuid2Class3:
    return "dynamic-guid2-class3";
  case ActorPayloadProbeMode::DynamicActorGuid2ContentEmpty:
    return "dynamic-guid2-content-empty";
  case ActorPayloadProbeMode::MustMapNoneThenGuid2:
    return "mustmap-none-guid2";
  case ActorPayloadProbeMode::MustMapGuid2ThenGuid2:
    return "mustmap-guid2";
  case ActorPayloadProbeMode::MustMapGuid2Guid4ThenGuid2:
    return "mustmap-guid2-guid4";
  case ActorPayloadProbeMode::ExportCount0ThenGuid2:
    return "export-count0-guid2";
  case ActorPayloadProbeMode::ExportGuid2ActorPathThenGuid2:
    return "export-guid2-actor-path";
  case ActorPayloadProbeMode::ExportGuid2ClassPathThenGuid2:
    return "export-guid2-class-path";
  }
  return "?";
}

const char *name_wire_mode_name(NameWireMode mode) {
  switch (mode) {
  case NameWireMode::StaticSerializeNameStringControl:
    return "static-serialize-name-string-Control";
  case NameWireMode::SmallHardcodedIndexProbe:
    return "small-hardcoded-index-probe";
  case NameWireMode::LegacyChannelTypeControlProbe:
    return "legacy-channel-type-control-probe";
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

  // UE5.7.x NetConnection reads one bHasPacketInfoPayload bit immediately
  // after FNetPacketNotify when PacketEngineNetVer >= JitterInHeader. If it
  // is true, it then reads a 10-bit jitter clock and one bHasServerFrameTime
  // bit. Real UE clients in our captures set this bit and write jitter=1023,
  // so consume the whole packet-info payload before probing bunches.
  bool has_packet_info_payload = false;
  if (!r.read_bit(has_packet_info_payload))
    return PacketNotifyHeaderMini{};
  if (has_packet_info_payload) {
    uint64_t jitter_clock = 0;
    if (!r.read_bits_u64(NumBitsForJitterClockTimeInHeader, jitter_clock))
      return PacketNotifyHeaderMini{};

    bool has_server_frame_time = false;
    if (!r.read_bit(has_server_frame_time))
      return PacketNotifyHeaderMini{};

    // Client->server packets should not include a frame-time byte here. If a
    // future capture does, consume it so the bunch scanner remains aligned.
    if (has_server_frame_time) {
      uint8_t frame_time = 0;
      if (!r.read_u8(frame_time))
        return PacketNotifyHeaderMini{};
    }
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
  // Important: TSequenceHistory bit 0 corresponds to the current AckedSeq
  // when AckCount == 1 on the receiver. A zero word NAKs the client packet
  // we just processed; bit0=1 ACKs it.
  uint32_t packed = 0;
  packed |= (uint32_t(seq) & (MaxPacketId - 1))
            << (PacketNotifyHistoryWordCountBits + PacketNotifySeqBits);
  packed |= (uint32_t(acked_seq) & (MaxPacketId - 1))
            << PacketNotifyHistoryWordCountBits;
  packed |= 0; // one history word => count-minus-one 0
  w.write_u32(packed);
  w.write_u32(1); // ack history bit0=1 => AckedSeq itself was delivered
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

static void
write_static_serialize_name_string_path(BitWriter &w,
                                        const std::string &plain_name) {
  // CoreNet.cpp, UPackageMap::StaticSerializeName save path:
  //
  //   const EName* InEName = InName.ToEName();
  //   uint8 bHardcoded = InEName && ShouldReplicateAsInteger(*InEName, InName);
  //   Ar.SerializeBits(&bHardcoded, 1);
  //   if (bHardcoded)
  //       Ar.SerializeIntPacked(NameIndex);
  //   else
  //       Ar << FString(PlainName) << int32(Number);
  //
  // The load path accepts either representation. We deliberately use the
  // string fallback for NAME_Control so we do not need the private numeric
  // EName::Control index from UnrealNames.inl.
  w.write_bit(false);                   // bHardcoded = 0 => string fallback
  write_ue_fstring_ansi(w, plain_name); // FName plain name string
  write_i32(w, 0);                      // FName number
}

static void write_static_serialize_name_control_string_path(BitWriter &w) {
  write_static_serialize_name_string_path(w, "Control");
}

static void write_fname_control(BitWriter &w, NameWireMode mode) {
  switch (mode) {
  case NameWireMode::StaticSerializeNameStringControl:
    write_static_serialize_name_control_string_path(w);
    return;

  case NameWireMode::SmallHardcodedIndexProbe:
    // Optional probe only. Real exact hardcoded path would be:
    //   bit 1 + SerializeIntPacked((uint32)EName::Control)
    // Uploading/searching UnrealNames.inl could replace this value, but
    // the string path above should already be accepted by StaticSerializeName.
    w.write_bit(true);
    w.write_int_packed(0);
    return;

  case NameWireMode::LegacyChannelTypeControlProbe:
    // Pre-ChannelNames path in UNetConnection::ReceivedPacket reads
    // Reader.ReadInt(CHTYPE_MAX), with CHTYPE_Control == 1 and
    // CHTYPE_MAX == 8, so this is three LSB-first bits: 001.
    w.write_int_wrapped(1, 8);
    return;
  }
}

static void write_control_message_payload(BitWriter &w,
                                          const ControlReplyBuildInput &in) {
  // DataChannel.h confirms UE5.7.4 control messages are:
  //   NMT_Challenge = 3, params: FString
  //   NMT_Welcome   = 1, params: FString LevelName, FString GameName, FString
  //   RedirectURL
  // TNetControlMessageImpl::Send serializes the uint8 message id first and
  // then serializes each parameter with FArchive::operator<<.
  w.write_u8(in.message_id);

  if (!in.message_strings.empty()) {
    for (const std::string &s : in.message_strings) {
      write_ue_fstring_ansi(w, s);
    }
  } else {
    write_ue_fstring_ansi(w, in.message_text);
  }
}

std::vector<uint8_t>
build_experimental_ack_only_packet(const UEHandshake &response,
                                   uint16_t last_client_packet_seq,
                                   uint16_t next_server_packet_seq) {
  uint16_t server_seq = 0, client_seq = 0;
  extract_sequences_from_cookie(response, server_seq, client_seq);

  const uint16_t packet_seq =
      next_server_packet_seq ? next_server_packet_seq : server_seq;
  const uint16_t ack_seq =
      last_client_packet_seq ? last_client_packet_seq : client_seq;

  BitWriter normal;
  write_packet_notify_header(normal, packet_seq, ack_seq);

  // Match the post-handshake PacketEngineNetVer >= JitterInHeader shape.
  normal.write_bit(true);
  normal.write_int_wrapped(MaxJitterClockTimeValue,
                           MaxJitterClockTimeValue + 1);
  normal.write_bit(false);

  // No bunch payload: just the NetConnection packet terminator. PacketHandler
  // then gets its own outer terminator below, same as real accepted packets.
  normal.write_termination_bit();

  BitWriter out;
  out.write_bits_u64(response.session_id & 0x3, SessionIdBits);
  out.write_bits_u64(response.client_id & 0x7, ClientIdBits);
  out.write_bit(false); // bHandshakePacket=0
  out.append_bits(normal);
  out.write_termination_bit();
  return out.bytes();
}

std::vector<uint8_t> build_experimental_empty_actor_channel_open_probe(
    const UEHandshake &response, uint16_t last_client_packet_seq,
    uint16_t next_server_packet_seq, uint16_t actor_channel_index,
    uint16_t next_out_reliable_actor_ch,
    ActorChannelNameWireMode actor_name_mode,
    ActorPayloadProbeMode payload_mode,
    const std::string &actor_class_path_hint) {
  uint16_t server_seq = 0, client_seq = 0;
  extract_sequences_from_cookie(response, server_seq, client_seq);

  const uint16_t packet_seq =
      next_server_packet_seq ? next_server_packet_seq : server_seq;
  const uint16_t ack_seq =
      last_client_packet_seq ? last_client_packet_seq : client_seq;

  BitWriter normal;
  write_packet_notify_header(normal, packet_seq, ack_seq);

  // PacketEngineNetVer >= JitterInHeader packet-info payload.
  normal.write_bit(true);
  normal.write_int_wrapped(MaxJitterClockTimeValue,
                           MaxJitterClockTimeValue + 1);
  normal.write_bit(false);

  // Experimental minimal actor-channel open probe. This is NOT real actor
  // replication yet. It opens a reliable channel with ChName=Actor and zero
  // bunch payload so we can see whether the client accepts the channel header
  // shape or closes/retries. Real SpawnPlayActor/replication will need a
  // PackageMap/NetGUID-exported actor payload after this milestone.
  normal.write_bit(true);  // bIsOpenOrClose
  normal.write_bit(true);  // bOpen
  normal.write_bit(false); // bClose
  normal.write_bit(false); // bIsReplicationPaused
  normal.write_bit(true);  // bReliable
  normal.write_int_packed(actor_channel_index);
  const bool has_must_map_prefix =
      payload_mode == ActorPayloadProbeMode::MustMapNoneThenGuid2 ||
      payload_mode == ActorPayloadProbeMode::MustMapGuid2ThenGuid2 ||
      payload_mode == ActorPayloadProbeMode::MustMapGuid2Guid4ThenGuid2;
  const bool has_package_map_exports =
      payload_mode == ActorPayloadProbeMode::ExportCount0ThenGuid2 ||
      payload_mode == ActorPayloadProbeMode::ExportGuid2ActorPathThenGuid2 ||
      payload_mode == ActorPayloadProbeMode::ExportGuid2ClassPathThenGuid2;
  normal.write_bit(has_package_map_exports); // bHasPackageMapExports
  normal.write_bit(has_must_map_prefix);     // bHasMustBeMappedGUIDs
  normal.write_bit(false);                   // bPartial
  normal.write_int_wrapped(next_out_reliable_actor_ch & (MaxChSequence - 1),
                           MaxChSequence);
  if (actor_name_mode == ActorChannelNameWireMode::LegacyChannelTypeActor) {
    // NetConnection.cpp pre-ChannelNames branch:
    //   Reader.ReadInt(CHTYPE_MAX) where CHTYPE_Actor == 2 and CHTYPE_MAX == 8.
    // The v35 string-name actor probe was understood as a bunch but rejected
    // with BunchWrongChannelType, which strongly indicates this client path
    // wants the legacy channel type enum here for actor-channel opens.
    normal.write_int_wrapped(2, 8);
  } else {
    write_static_serialize_name_string_path(normal, "Actor");
  }

  // Build the actor-bunch payload into its own bitstream first so the bunch
  // header can write the exact payload bit count.
  BitWriter actor_payload;

  auto write_export_prefix_count0 = [&]() {
    // Diagnostic PackageMap export boundary probe. The exact
    // UPackageMapClient export format lives outside the uploaded source, so
    // this starts with the most likely compact-count boundary. If the client
    // reacts differently than the non-export modes, bHasPackageMapExports is
    // reaching ReceiveNetGUIDBunch before SerializeNewActor.
    actor_payload.write_int_packed(0);
  };
  auto write_export_prefix_one_path = [&](uint32_t guid_value,
                                          const std::string &path) {
    // Speculative one-export shape: count, GUID, outer GUID, path string,
    // checksum/flags placeholder. This is not a real PackageMap exporter
    // yet; it is a boundary probe to test whether path-bearing export data
    // changes client behavior versus bare GUID payloads.
    actor_payload.write_int_packed(1);
    actor_payload.write_int_packed(guid_value);
    actor_payload.write_int_packed(0);
    write_ue_fstring_ansi(actor_payload, path);
    actor_payload.write_int_packed(0);
  };

  switch (payload_mode) {
  case ActorPayloadProbeMode::Empty:
    break;
  case ActorPayloadProbeMode::ZeroByte:
    actor_payload.write_u8(0);
    break;
  case ActorPayloadProbeMode::FourZeroBytes:
    actor_payload.write_u32(0);
    break;
  case ActorPayloadProbeMode::PackedNetGuidZero:
    // Likely first SerializeObject/SerializeNewActor field: an actor
    // FNetworkGUID serialized as packed int. Zero is an invalid/null
    // object probe. If the client responds with object/guid failure,
    // we know this boundary is plausible.
    actor_payload.write_int_packed(0);
    break;
  case ActorPayloadProbeMode::PackedNetGuidOne:
    // Minimal non-zero actor NetGUID probe. Not enough to spawn, but
    // enough to distinguish empty-payload timeout from NetGUID parsing.
    actor_payload.write_int_packed(1);
    break;
  case ActorPayloadProbeMode::PackedNetGuidOneClassZero:
    // Actor NetGUID + null class/object GUID probe. This approximates
    // the next SerializeObject boundary without path exports.
    actor_payload.write_int_packed(1);
    actor_payload.write_int_packed(0);
    break;
  case ActorPayloadProbeMode::PackedNetGuidOneClassOne:
    // Actor NetGUID + non-zero class/object GUID probe. Still no path
    // exports, so a clean NetGUID/object-resolution failure is expected.
    actor_payload.write_int_packed(1);
    actor_payload.write_int_packed(1);
    break;
  case ActorPayloadProbeMode::DynamicActorGuid2:
    // FNetworkGUID value layout: low bit is static flag, upper bits are index.
    // Value 2 => dynamic GUID with index 1, a better approximation for a newly
    // spawned replicated actor than odd/static value 1.
    actor_payload.write_int_packed(2);
    break;
  case ActorPayloadProbeMode::DynamicActorGuid2Class0:
    actor_payload.write_int_packed(2); // dynamic actor GUID
    actor_payload.write_int_packed(0); // null/default class/archetype probe
    break;
  case ActorPayloadProbeMode::DynamicActorGuid2Class1:
    actor_payload.write_int_packed(2); // dynamic actor GUID
    actor_payload.write_int_packed(1); // odd/static class/archetype probe
    break;
  case ActorPayloadProbeMode::DynamicActorGuid2Class3:
    actor_payload.write_int_packed(2); // dynamic actor GUID
    actor_payload.write_int_packed(
        3); // another small static class/archetype probe
    break;
  case ActorPayloadProbeMode::DynamicActorGuid2ContentEmpty:
    // Actor GUID followed by an empty content block header as if
    // SerializeNewActor succeeded and ProcessBunch started reading actor
    // content. This is expected to fail unless GUID/class resolution also
    // works, but it tells us whether the reader advances past the initial actor
    // GUID boundary.
    actor_payload.write_int_packed(2); // dynamic actor GUID
    actor_payload.write_bit(false);    // bHasRepLayout = 0
    actor_payload.write_bit(true);     // bIsActor = 1
    actor_payload.write_int_packed(0); // NumPayloadBits = 0
    break;
  case ActorPayloadProbeMode::MustMapNoneThenGuid2:
    // bHasMustBeMappedGUIDs=1 with NumMustBeMappedGUIDs=0, then the same
    // dynamic actor GUID. This isolates whether the client accepts the
    // must-map prefix framing at all. UE serializes the count as uint16.
    actor_payload.write_u16(0);
    actor_payload.write_int_packed(2);
    break;
  case ActorPayloadProbeMode::MustMapGuid2ThenGuid2:
    // Prefix one must-map GUID (dynamic actor GUID 2), then serialize the
    // same dynamic actor GUID as the new actor object. Without a real export
    // this may fail, but a different failure proves the must-map boundary.
    actor_payload.write_u16(1);
    actor_payload.write_int_packed(2);
    actor_payload.write_int_packed(2);
    break;
  case ActorPayloadProbeMode::MustMapGuid2Guid4ThenGuid2:
    // Prefix two dynamic GUIDs then the actor GUID. Useful if class/archetype
    // has to be in the must-map prefix before SerializeNewActor advances.
    actor_payload.write_u16(2);
    actor_payload.write_int_packed(2);
    actor_payload.write_int_packed(4);
    actor_payload.write_int_packed(2);
    break;
  case ActorPayloadProbeMode::ExportCount0ThenGuid2:
    write_export_prefix_count0();
    actor_payload.write_int_packed(2);
    break;
  case ActorPayloadProbeMode::ExportGuid2ActorPathThenGuid2:
    write_export_prefix_one_path(2, "/Script/Engine.Actor");
    actor_payload.write_int_packed(2);
    break;
  case ActorPayloadProbeMode::ExportGuid2ClassPathThenGuid2:
    write_export_prefix_one_path(
        2, actor_class_path_hint.empty()
               ? std::string("/Script/Engine.PlayerController")
               : actor_class_path_hint);
    actor_payload.write_int_packed(2);
    break;
  }
  normal.write_int_wrapped(actor_payload.bit_count(), 1024 * 8);
  normal.append_bits(actor_payload);

  normal.write_termination_bit();

  BitWriter out;
  out.write_bits_u64(response.session_id & 0x3, SessionIdBits);
  out.write_bits_u64(response.client_id & 0x7, ClientIdBits);
  out.write_bit(false);
  out.append_bits(normal);
  out.write_termination_bit();
  return out.bytes();
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

  // PacketEngineNetVer >= JitterInHeader path expects packet-info after
  // PacketNotify. Real UE packets in the captures set bHasPacketInfoPayload=1,
  // write a 10-bit jitter clock value, then bHasServerFrameTime. Match that
  // shape instead of sending a bare false bit. Use max jitter to mean "ignore
  // jitter" and no server frame-time byte.
  normal.write_bit(true);
  normal.write_int_wrapped(MaxJitterClockTimeValue,
                           MaxJitterClockTimeValue + 1);
  normal.write_bit(false);

  BitWriter bunch_payload;
  write_control_message_payload(bunch_payload, in);

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

  // Source-accurate UE5.7.4 SendRawBunch behavior: Bunch.ChName is serialized
  // when the bunch is open OR reliable. v16 tested this but still used an
  // invalid reliable channel sequence (1 instead of seed+1). v18 combines the
  // source-accurate channel-name field with the corrected seeded ChSequence.
  write_fname_control(normal, in.name_mode);

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

  // UE packets still pass through PacketHandler after the StatelessConnect
  // component prepends SessionID/ClientID/bHandshakePacket. PacketHandler
  // reserves/strips its own trailing termination marker, while the wrapped
  // UNetConnection payload also contains the normal NetConnection
  // termination bit. Earlier builds only wrote the inner NetConnection
  // termination bit, producing packets ending in 0x01; real client packets
  // typically end with two termination markers (often visible as 0x0c when
  // bit-aligned). Write the outer PacketHandler termination marker too.
  out.write_termination_bit();

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

static void apply_stateful_sequences(ControlReplyBuildInput &in,
                                     uint16_t next_server_packet_seq,
                                     uint16_t next_out_reliable_ch0) {
  if (next_server_packet_seq != 0) {
    in.next_server_packet_seq = next_server_packet_seq;
  }
  in.next_out_reliable_ch0 = next_out_reliable_ch0 & (MaxChSequence - 1);
}

std::vector<uint8_t> build_experimental_nmt_challenge_stateful(
    const UEHandshake &response, uint16_t last_client_packet_seq,
    uint16_t next_server_packet_seq, uint16_t next_out_reliable_ch0) {
  auto in = base_input(response, last_client_packet_seq);
  apply_stateful_sequences(in, next_server_packet_seq, next_out_reliable_ch0);
  in.message_id = NMT_Challenge;
  in.message_strings = {"00000000"};
  in.name_mode = NameWireMode::StaticSerializeNameStringControl;
  return build_experimental_control_reply_packet(in);
}

std::vector<uint8_t> build_experimental_nmt_welcome_stateful_custom(
    const UEHandshake &response, uint16_t last_client_packet_seq,
    uint16_t next_server_packet_seq, uint16_t next_out_reliable_ch0,
    const std::string &level_name, const std::string &game_name,
    const std::string &redirect_url) {
  auto in = base_input(response, last_client_packet_seq);
  apply_stateful_sequences(in, next_server_packet_seq, next_out_reliable_ch0);
  in.message_id = NMT_Welcome;
  in.message_strings = {level_name, game_name, redirect_url};
  in.name_mode = NameWireMode::StaticSerializeNameStringControl;
  return build_experimental_control_reply_packet(in);
}

std::vector<uint8_t> build_experimental_nmt_failure_stateful_custom(
    const UEHandshake &response, uint16_t last_client_packet_seq,
    uint16_t next_server_packet_seq, uint16_t next_out_reliable_ch0,
    const std::string &failure_text) {
  auto in = base_input(response, last_client_packet_seq);
  apply_stateful_sequences(in, next_server_packet_seq, next_out_reliable_ch0);
  in.message_id = NMT_Failure;
  in.message_strings = {failure_text};
  in.name_mode = NameWireMode::StaticSerializeNameStringControl;
  return build_experimental_control_reply_packet(in);
}

std::vector<uint8_t> build_experimental_nmt_welcome_stateful(
    const UEHandshake &response, uint16_t last_client_packet_seq,
    uint16_t next_server_packet_seq, uint16_t next_out_reliable_ch0) {
  return build_experimental_nmt_welcome_stateful_custom(
      response, last_client_packet_seq, next_server_packet_seq,
      next_out_reliable_ch0, "/Game/Maps/Minimal",
      "/Script/Engine.GameModeBase", "");
}

std::vector<uint8_t>
build_experimental_nmt_challenge(const UEHandshake &response,
                                 uint16_t last_client_packet_seq) {
  auto in = base_input(response, last_client_packet_seq);
  return build_experimental_nmt_challenge_stateful(
      response, last_client_packet_seq, in.next_server_packet_seq,
      in.next_out_reliable_ch0);
}

std::vector<uint8_t>
build_experimental_nmt_welcome(const UEHandshake &response,
                               uint16_t last_client_packet_seq) {
  auto in = base_input(response, last_client_packet_seq);
  return build_experimental_nmt_welcome_stateful(
      response, last_client_packet_seq, in.next_server_packet_seq,
      in.next_out_reliable_ch0);
}

std::vector<std::vector<uint8_t>>
build_experimental_nmt_challenge_candidates(const UEHandshake &response,
                                            uint16_t last_client_packet_seq) {
  return {build_experimental_nmt_challenge(response, last_client_packet_seq)};
}

std::vector<std::vector<uint8_t>>
build_experimental_nmt_welcome_candidates(const UEHandshake &response,
                                          uint16_t last_client_packet_seq) {
  return {build_experimental_nmt_welcome(response, last_client_packet_seq)};
}

} // namespace ue574
