#include "control_channel_probe.h"
#include "control_channel_writer.h"
#include "udp_util.h"
#include "ue57_protocol.h"

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <unordered_map>

static volatile sig_atomic_t g_running = 1;

static void on_signal(int) { g_running = 0; }

static uint64_t now_seconds() { return (uint64_t)time(nullptr); }

struct Session {
  ue574::SessionPhase phase = ue574::SessionPhase::CookieValidated;
  uint64_t created = 0;
  uint64_t last_seen = 0;
  bool real_ue = false;
  ue574::UEHandshake handshake{};
  uint16_t server_sequence = 0;
  uint16_t client_sequence = 0;
  uint16_t last_client_packet_seq = 0;
  uint16_t next_server_packet_seq = 0;
  uint16_t next_out_reliable_ch0 = 0;
  uint16_t next_out_reliable_actor = 0;
  uint16_t next_out_reliable_datastream = 0;
  bool sent_nmt_challenge = false;
  bool sent_nmt_welcome = false;
  uint16_t last_welcome_packet_seq = 0;
  uint16_t last_ack_only_client_seq = 0;
  bool saw_exact_netspeed = false;
  bool saw_exact_join = false;
  bool saw_direct_netspeed = false;
  bool saw_direct_join = false;
  uint16_t first_exact_join_client_seq = 0;
  uint16_t first_direct_join_client_seq = 0;
  uint32_t post_welcome_client_packets = 0;
  uint32_t ack_only_packets_sent = 0;
  bool announced_waiting_for_actor_replication = false;
  bool announced_post_welcome_ack_loop = false;
  bool saw_direct_login_after_welcome = false;
  uint16_t first_direct_login_after_welcome_seq = 0;
  bool sent_post_welcome_failure = false;
  bool sent_empty_actor_probe = false;
  bool sent_datastream_open_probe = false;
  uint16_t last_datastream_open_packet_seq = 0;
  bool datastream_open_packet_acked = false;
  bool announced_datastream_open_packet_acked = false;
  uint16_t last_actor_probe_packet_seq = 0;
  bool actor_probe_packet_acked = false;
  bool announced_actor_probe_packet_acked = false;
  bool sent_actor_followup_probe = false;
  uint16_t last_actor_followup_packet_seq = 0;
  bool actor_followup_packet_acked = false;
  bool announced_actor_followup_packet_acked = false;
  bool saw_actor_channel_failure = false;
  uint16_t first_actor_channel_failure_seq = 0;
  bool saw_actor_probe_late_pressure = false;
  uint16_t first_actor_probe_late_pressure_seq = 0;
  bool saw_bunch_wrong_channel_type = false;
  uint16_t first_bunch_wrong_channel_type_seq = 0;
  uint16_t last_failure_packet_seq = 0;
  bool saw_failure_received = false;
  uint16_t first_failure_received_client_seq = 0;
  bool saw_tail_join = false;
  uint16_t first_tail_join_client_seq = 0;
  uint16_t max_client_seq_seen = 0;
  uint16_t max_client_acked_seen = 0;
};

static bool read_bits_lsb_local(const uint8_t *data, size_t n, uint32_t bit_pos,
                                uint32_t bit_count, uint64_t &out) {
  if (!data || bit_count > 64 || bit_pos + bit_count > n * 8u) {
    return false;
  }
  out = 0;
  for (uint32_t i = 0; i < bit_count; ++i) {
    const uint32_t absolute = bit_pos + i;
    const uint8_t b = data[absolute >> 3];
    const uint8_t bit = (uint8_t)((b >> (absolute & 7u)) & 1u);
    out |= (uint64_t)bit << i;
  }
  return true;
}

static bool read_u8_at_bit(const uint8_t *data, size_t n, uint32_t bit_pos,
                           uint8_t &out) {
  uint64_t v = 0;
  if (!read_bits_lsb_local(data, n, bit_pos, 8, v)) {
    return false;
  }
  out = (uint8_t)v;
  return true;
}

static bool read_u32_at_bit(const uint8_t *data, size_t n, uint32_t bit_pos,
                            uint32_t &out) {
  uint64_t v = 0;
  if (!read_bits_lsb_local(data, n, bit_pos, 32, v)) {
    return false;
  }
  out = (uint32_t)v;
  return true;
}

static bool contains_ascii_token(const uint8_t *data, size_t n,
                                 const char *token) {
  const size_t m = strlen(token);
  if (!data || !token || m == 0 || n < m) {
    return false;
  }
  for (size_t i = 0; i + m <= n; ++i) {
    if (memcmp(data + i, token, m) == 0) {
      return true;
    }
  }
  return false;
}

static bool looks_like_real_login_payload(const uint8_t *data, size_t n) {
  // The broad bit-probe can find false NMT_Login bytes in tiny keepalive/ack
  // packets. The real UE NMT_Login bunch is much larger and includes the
  // client URL and platform/id strings in plain ANSI FString form. Prefer
  // these byte-level signatures before sending NMT_Welcome.
  if (n < 64) {
    return false;
  }
  return contains_ascii_token(data, n, "?Name=") ||
         contains_ascii_token(data, n, "Name=") ||
         contains_ascii_token(data, n, "NULL");
}

static bool has_post_welcome_join_tail(const uint8_t *data, size_t n) {
  // In the real UE5.7.4 client captures, the first post-Welcome join-side
  // compact control packet is 19 bytes and ends in: 00 09 03. The 0x09 byte
  // is the UE5.7.4 NMT_Join control id. Earlier exact-bit decoding misses it
  // because this packet is compact/partially bit-packed rather than a full
  // clean bunch at pn.bits_consumed. Treat this as a strong join-side signal,
  // not as a complete actor-channel implementation.
  return data && n >= 3 && data[n - 3] == 0x00 &&
         data[n - 2] == ue574::NMT_Join && data[n - 1] == 0x03;
}

static const ue574::BunchProbe *
first_exact_control_candidate(const ue574::PostHandshakeProbeReport &report) {
  if (report.candidates.empty()) {
    return nullptr;
  }
  const ue574::BunchProbe &c = report.candidates.front();
  if (c.channel_index == 0 && c.first_payload_byte != 0xff) {
    return &c;
  }
  return nullptr;
}

static void print_handshake_summary(const ue574::UEHandshake &h) {
  printf("  UE handshake: type=%s(%u) min=%u cur=%u sent=%u session=%u "
         "client=%u netver=%u features=0x%04x restart=%u ts=%.3f\n",
         ue574::handshake_type_name(h.packet_type), (unsigned)h.packet_type,
         (unsigned)h.remote_min_version, (unsigned)h.remote_cur_version,
         (unsigned)h.remote_sent_count, (unsigned)h.session_id,
         (unsigned)h.client_id, (unsigned)h.network_version,
         (unsigned)h.network_features, h.restart ? 1u : 0u, h.timestamp);
}

int main(int argc, char **argv) {
  uint16_t port = 7777;
  const char *binlog_path = nullptr;
  bool experimental_control_replies = false;
  bool verbose_packets = false;
  std::string welcome_level_name = "/Game/Maps/Minimal";
  std::string welcome_game_name = "/Script/Engine.GameModeBase";
  std::string welcome_redirect_url = "";
  std::string planned_player_controller_class = "";
  std::string planned_pawn_class = "";
  uint32_t post_welcome_ack_every = 8;
  uint32_t post_welcome_max_ack_only = 0;  // 0 = unlimited
  uint32_t post_welcome_failure_after = 0; // 0 = disabled
  std::string post_welcome_failure_text =
      "Nano endpoint reached post-Welcome NetSpeed/join phase; actor "
      "replication is not implemented yet.";
  bool post_join_empty_actor_probe = false;
  uint32_t post_join_actor_probe_after = 1;
  uint16_t post_join_actor_channel = 3;
  ue574::ActorChannelNameWireMode post_join_actor_name_mode =
      ue574::ActorChannelNameWireMode::StaticSerializeNameStringActor;
  ue574::ActorPayloadProbeMode post_join_actor_payload_mode =
      ue574::ActorPayloadProbeMode::Empty;
  bool post_join_actor_followup_probe = false;
  uint32_t post_join_actor_followup_after = 2;
  bool post_join_datastream_open_probe = false;
  uint32_t post_join_datastream_open_after = 1;
  uint16_t post_join_datastream_channel = 2;
  uint16_t post_join_datastream_wire_channel =
      0; // 0 = auto/calibrated from logical channel
  ue574::DataStreamHeaderMode post_join_datastream_header_mode =
      ue574::DataStreamHeaderMode::Reliable;

  for (int i = 1; i < argc; ++i) {
    if (!strcmp(argv[i], "--port") && i + 1 < argc) {
      long p = strtol(argv[++i], nullptr, 10);
      if (p <= 0 || p > 65535) {
        fprintf(stderr, "bad port\n");
        return 2;
      }
      port = (uint16_t)p;
    } else if (!strcmp(argv[i], "--binlog") && i + 1 < argc) {
      binlog_path = argv[++i];
    } else if (!strcmp(argv[i], "--experimental-control-replies")) {
      experimental_control_replies = true;
    } else if (!strcmp(argv[i], "--verbose-packets")) {
      verbose_packets = true;
    } else if (!strcmp(argv[i], "--level-name") && i + 1 < argc) {
      welcome_level_name = argv[++i];
    } else if (!strcmp(argv[i], "--game-name") && i + 1 < argc) {
      welcome_game_name = argv[++i];
    } else if (!strcmp(argv[i], "--redirect-url") && i + 1 < argc) {
      welcome_redirect_url = argv[++i];
    } else if (!strcmp(argv[i], "--player-controller-class") && i + 1 < argc) {
      planned_player_controller_class = argv[++i];
    } else if (!strcmp(argv[i], "--pawn-class") && i + 1 < argc) {
      planned_pawn_class = argv[++i];
    } else if (!strcmp(argv[i], "--post-welcome-ack-every") && i + 1 < argc) {
      long v = strtol(argv[++i], nullptr, 10);
      if (v < 0 || v > 1000000) {
        fprintf(stderr, "bad --post-welcome-ack-every; use 0 to disable or a "
                        "positive packet interval\n");
        return 2;
      }
      post_welcome_ack_every = (uint32_t)v;
    } else if (!strcmp(argv[i], "--post-welcome-max-ack-only") &&
               i + 1 < argc) {
      long v = strtol(argv[++i], nullptr, 10);
      if (v < 0 || v > 1000000) {
        fprintf(stderr,
                "bad --post-welcome-max-ack-only; use 0 for unlimited\n");
        return 2;
      }
      post_welcome_max_ack_only = (uint32_t)v;
    } else if (!strcmp(argv[i], "--post-welcome-failure-after") &&
               i + 1 < argc) {
      long v = strtol(argv[++i], nullptr, 10);
      if (v < 0 || v > 1000000) {
        fprintf(stderr, "bad --post-welcome-failure-after; use 0 to disable or "
                        "a positive post-Welcome client-packet count\n");
        return 2;
      }
      post_welcome_failure_after = (uint32_t)v;
    } else if (!strcmp(argv[i], "--post-welcome-failure-text") &&
               i + 1 < argc) {
      post_welcome_failure_text = argv[++i];
    } else if (!strcmp(argv[i], "--post-join-empty-actor-probe")) {
      post_join_empty_actor_probe = true;
    } else if (!strcmp(argv[i], "--post-join-actor-probe-after") &&
               i + 1 < argc) {
      long v = strtol(argv[++i], nullptr, 10);
      if (v < 0 || v > 1000000) {
        fprintf(stderr, "bad --post-join-actor-probe-after; use a non-negative "
                        "post-Welcome packet count\n");
        return 2;
      }
      post_join_actor_probe_after = (uint32_t)v;
    } else if (!strcmp(argv[i], "--post-join-actor-channel") && i + 1 < argc) {
      long v = strtol(argv[++i], nullptr, 10);
      if (v < 1 || v > 1023) {
        fprintf(stderr, "bad --post-join-actor-channel; use 1..1023\n");
        return 2;
      }
      post_join_actor_channel = (uint16_t)v;
    } else if (!strcmp(argv[i], "--post-join-actor-followup-probe")) {
      post_join_actor_followup_probe = true;
    } else if (!strcmp(argv[i], "--post-join-actor-followup-after") &&
               i + 1 < argc) {
      long v = strtol(argv[++i], nullptr, 10);
      if (v < 0 || v > 1000000) {
        fprintf(stderr, "bad --post-join-actor-followup-after; use a "
                        "non-negative post-Welcome packet count\n");
        return 2;
      }
      post_join_actor_followup_after = (uint32_t)v;
    } else if (!strcmp(argv[i], "--post-join-datastream-open-probe")) {
      post_join_datastream_open_probe = true;
    } else if (!strcmp(argv[i], "--post-join-datastream-open-after") &&
               i + 1 < argc) {
      long v = strtol(argv[++i], nullptr, 10);
      if (v < 0 || v > 1000000) {
        fprintf(stderr, "bad --post-join-datastream-open-after; use a "
                        "non-negative post-Welcome packet count\n");
        return 2;
      }
      post_join_datastream_open_after = (uint32_t)v;
    } else if (!strcmp(argv[i], "--post-join-datastream-channel") &&
               i + 1 < argc) {
      long v = strtol(argv[++i], nullptr, 10);
      if (v < 0 || v > 1023) {
        fprintf(stderr, "bad --post-join-datastream-channel; use 0..1023\n");
        return 2;
      }
      post_join_datastream_channel = (uint16_t)v;
    } else if (!strcmp(argv[i], "--post-join-datastream-wire-channel") &&
               i + 1 < argc) {
      long v = strtol(argv[++i], nullptr, 10);
      if (v < 0 || v > 1023) {
        fprintf(stderr,
                "bad --post-join-datastream-wire-channel; use 0..1023\n");
        return 2;
      }
      post_join_datastream_wire_channel = (uint16_t)v;
    } else if (!strcmp(argv[i], "--post-join-datastream-header-mode") &&
               i + 1 < argc) {
      const char *mode = argv[++i];
      if (!strcmp(mode, "reliable") || !strcmp(mode, "source")) {
        post_join_datastream_header_mode =
            ue574::DataStreamHeaderMode::Reliable;
      } else if (!strcmp(mode, "open-reliable") || !strcmp(mode, "open")) {
        post_join_datastream_header_mode =
            ue574::DataStreamHeaderMode::OpenReliable;
      } else if (!strcmp(mode, "pad-before-chindex") || !strcmp(mode, "pad1")) {
        post_join_datastream_header_mode =
            ue574::DataStreamHeaderMode::PadBeforeChIndex;
      } else {
        fprintf(stderr, "bad --post-join-datastream-header-mode; use reliable, "
                        "open-reliable, or pad-before-chindex\n");
        return 2;
      }
    } else if (!strcmp(argv[i], "--post-join-actor-name-mode") &&
               i + 1 < argc) {
      const char *mode = argv[++i];
      if (!strcmp(mode, "legacy") || !strcmp(mode, "legacy-actor") ||
          !strcmp(mode, "legacy-CHTYPE_Actor")) {
        post_join_actor_name_mode =
            ue574::ActorChannelNameWireMode::LegacyChannelTypeActor;
      } else if (!strcmp(mode, "string") || !strcmp(mode, "static-string") ||
                 !strcmp(mode, "StaticSerializeName")) {
        post_join_actor_name_mode =
            ue574::ActorChannelNameWireMode::StaticSerializeNameStringActor;
      } else {
        fprintf(stderr,
                "bad --post-join-actor-name-mode; use legacy or string\n");
        return 2;
      }
    } else if (!strcmp(argv[i], "--post-join-actor-payload-mode") &&
               i + 1 < argc) {
      const char *mode = argv[++i];
      if (!strcmp(mode, "empty")) {
        post_join_actor_payload_mode = ue574::ActorPayloadProbeMode::Empty;
      } else if (!strcmp(mode, "zero8") || !strcmp(mode, "zero-byte") ||
                 !strcmp(mode, "one-zero-byte")) {
        post_join_actor_payload_mode = ue574::ActorPayloadProbeMode::ZeroByte;
      } else if (!strcmp(mode, "zero32") || !strcmp(mode, "four-zero-bytes")) {
        post_join_actor_payload_mode =
            ue574::ActorPayloadProbeMode::FourZeroBytes;
      } else if (!strcmp(mode, "netguid0") ||
                 !strcmp(mode, "packed-netguid0")) {
        post_join_actor_payload_mode =
            ue574::ActorPayloadProbeMode::PackedNetGuidZero;
      } else if (!strcmp(mode, "netguid1") ||
                 !strcmp(mode, "packed-netguid1")) {
        post_join_actor_payload_mode =
            ue574::ActorPayloadProbeMode::PackedNetGuidOne;
      } else if (!strcmp(mode, "netguid1-class0") ||
                 !strcmp(mode, "packed-netguid1-class0")) {
        post_join_actor_payload_mode =
            ue574::ActorPayloadProbeMode::PackedNetGuidOneClassZero;
      } else if (!strcmp(mode, "netguid1-class1") ||
                 !strcmp(mode, "packed-netguid1-class1")) {
        post_join_actor_payload_mode =
            ue574::ActorPayloadProbeMode::PackedNetGuidOneClassOne;
      } else if (!strcmp(mode, "dynamic-guid2") || !strcmp(mode, "dynguid2") ||
                 !strcmp(mode, "guid2")) {
        post_join_actor_payload_mode =
            ue574::ActorPayloadProbeMode::DynamicActorGuid2;
      } else if (!strcmp(mode, "dynamic-guid2-class0") ||
                 !strcmp(mode, "dynguid2-class0") ||
                 !strcmp(mode, "guid2-class0")) {
        post_join_actor_payload_mode =
            ue574::ActorPayloadProbeMode::DynamicActorGuid2Class0;
      } else if (!strcmp(mode, "dynamic-guid2-class1") ||
                 !strcmp(mode, "dynguid2-class1") ||
                 !strcmp(mode, "guid2-class1")) {
        post_join_actor_payload_mode =
            ue574::ActorPayloadProbeMode::DynamicActorGuid2Class1;
      } else if (!strcmp(mode, "dynamic-guid2-class3") ||
                 !strcmp(mode, "dynguid2-class3") ||
                 !strcmp(mode, "guid2-class3")) {
        post_join_actor_payload_mode =
            ue574::ActorPayloadProbeMode::DynamicActorGuid2Class3;
      } else if (!strcmp(mode, "dynamic-guid2-content-empty") ||
                 !strcmp(mode, "dynguid2-content-empty") ||
                 !strcmp(mode, "guid2-content-empty")) {
        post_join_actor_payload_mode =
            ue574::ActorPayloadProbeMode::DynamicActorGuid2ContentEmpty;
      } else if (!strcmp(mode, "mustmap-none-guid2") ||
                 !strcmp(mode, "mustmap-none")) {
        post_join_actor_payload_mode =
            ue574::ActorPayloadProbeMode::MustMapNoneThenGuid2;
      } else if (!strcmp(mode, "mustmap-guid2") ||
                 !strcmp(mode, "mustmap-guid2-guid2")) {
        post_join_actor_payload_mode =
            ue574::ActorPayloadProbeMode::MustMapGuid2ThenGuid2;
      } else if (!strcmp(mode, "mustmap-guid2-guid4") ||
                 !strcmp(mode, "mustmap-two")) {
        post_join_actor_payload_mode =
            ue574::ActorPayloadProbeMode::MustMapGuid2Guid4ThenGuid2;
      } else if (!strcmp(mode, "export-count0-guid2") ||
                 !strcmp(mode, "export-count0")) {
        post_join_actor_payload_mode =
            ue574::ActorPayloadProbeMode::ExportCount0ThenGuid2;
      } else if (!strcmp(mode, "export-guid2-actor-path") ||
                 !strcmp(mode, "export-actor-path")) {
        post_join_actor_payload_mode =
            ue574::ActorPayloadProbeMode::ExportGuid2ActorPathThenGuid2;
      } else if (!strcmp(mode, "export-guid2-class-path") ||
                 !strcmp(mode, "export-class-path")) {
        post_join_actor_payload_mode =
            ue574::ActorPayloadProbeMode::ExportGuid2ClassPathThenGuid2;
      } else if (!strcmp(mode, "serialize-newactor-pc-cdo") ||
                 !strcmp(mode, "realish-newactor")) {
        post_join_actor_payload_mode =
            ue574::ActorPayloadProbeMode::SerializeNewActorPlayerControllerCDO;
      } else {
        fprintf(stderr,
                "bad --post-join-actor-payload-mode; use empty, zero8, zero32, "
                "netguid0, netguid1, netguid1-class0, netguid1-class1, "
                "dynamic-guid2, dynamic-guid2-class0, dynamic-guid2-class1, "
                "dynamic-guid2-class3, dynamic-guid2-content-empty, "
                "mustmap-none-guid2, mustmap-guid2, mustmap-guid2-guid4, "
                "export-count0-guid2, export-guid2-actor-path, "
                "export-guid2-class-path, or serialize-newactor-pc-cdo\n");
        return 2;
      }
    } else {
      fprintf(
          stderr,
          "usage: %s [--port 7777] [--binlog packets.binlog] "
          "[--experimental-control-replies] [--verbose-packets] [--level-name "
          "/Game/Maps/Map] [--game-name /Script/Engine.GameModeBase] "
          "[--redirect-url URL] [--player-controller-class /Game/Foo.Foo_C] "
          "[--pawn-class /Game/Foo.Foo_C] [--post-welcome-ack-every N] "
          "[--post-welcome-max-ack-only N] [--post-welcome-failure-after N] "
          "[--post-welcome-failure-text TEXT] [--post-join-empty-actor-probe] "
          "[--post-join-actor-probe-after N] [--post-join-actor-channel N] "
          "[--post-join-actor-followup-probe] "
          "[--post-join-actor-followup-after N] "
          "[--post-join-datastream-open-probe] "
          "[--post-join-datastream-open-after N] "
          "[--post-join-datastream-channel N] "
          "[--post-join-datastream-wire-channel N] "
          "[--post-join-datastream-header-mode "
          "reliable|open-reliable|pad-before-chindex] "
          "[--post-join-actor-name-mode legacy|string] "
          "[--post-join-actor-payload-mode "
          "empty|zero8|zero32|netguid0|netguid1|netguid1-class0|netguid1-"
          "class1|dynamic-guid2|dynamic-guid2-class0|dynamic-guid2-class1|"
          "dynamic-guid2-class3|dynamic-guid2-content-empty|mustmap-none-guid2|"
          "mustmap-guid2|mustmap-guid2-guid4|export-count0-guid2|export-guid2-"
          "actor-path|export-guid2-class-path|serialize-newactor-pc-cdo]\n",
          argv[0]);
      return 2;
    }
  }

  FILE *binlog = nullptr;
  if (binlog_path) {
    binlog = fopen(binlog_path, "ab");
    if (!binlog) {
      fprintf(stderr, "failed to open binlog %s: %s\n", binlog_path,
              strerror(errno));
      return 1;
    }
  }

  signal(SIGINT, on_signal);
  signal(SIGTERM, on_signal);
  srand((unsigned)time(nullptr));

  udp_socket_t fd = udp_bind_any(port);
  if (!udp_socket_is_valid(fd)) {
    return 1;
  }

  printf("UE5 5.7.4 NanoS endpoint starter listening on UDP/%u\n",
         (unsigned)port);
  printf("mode: real StatelessConnect handshake attempt + post-handshake "
         "control-channel probe\n");
  printf("note: console is compact by default; use --verbose-packets for full "
         "per-packet probes/hex dumps\n");
  printf("post-Welcome ACK pacing: every %u client packet(s)%s\n",
         (unsigned)post_welcome_ack_every,
         post_welcome_max_ack_only ? " with max cap" : "");
  if (post_welcome_failure_after) {
    printf("post-Welcome diagnostic Failure: after %u client packet(s), "
           "text='%s'\n",
           (unsigned)post_welcome_failure_after,
           post_welcome_failure_text.c_str());
  }
  if (post_join_empty_actor_probe) {
    printf("post-Join actor-channel probe: enabled on channel %u after %u "
           "post-Welcome client packet(s), name-mode=%s payload-mode=%s\n",
           (unsigned)post_join_actor_channel,
           (unsigned)post_join_actor_probe_after,
           ue574::actor_channel_name_wire_mode_name(post_join_actor_name_mode),
           ue574::actor_payload_probe_mode_name(post_join_actor_payload_mode));
    if (post_join_actor_followup_probe) {
      printf("post-Join actor follow-up content probe: enabled after %u "
             "post-Welcome client packet(s), same channel/payload mode\n",
             (unsigned)post_join_actor_followup_after);
    }
  }
  printf("experimental control replies: %s\n",
         experimental_control_replies ? "enabled" : "disabled");
  if (experimental_control_replies) {
    printf("welcome payload: LevelName='%s' GameName='%s' RedirectURL='%s'\n",
           welcome_level_name.c_str(), welcome_game_name.c_str(),
           welcome_redirect_url.c_str());
    if (!planned_player_controller_class.empty() ||
        !planned_pawn_class.empty()) {
      printf("planned player hook: PlayerController='%s' Pawn='%s' (diagnostic "
             "only until actor-channel replication exists)\n",
             planned_player_controller_class.c_str(),
             planned_pawn_class.c_str());
    }
    if (welcome_level_name == "/Game/Maps/Minimal") {
      printf("warning: default LevelName is a placeholder; use --level-name "
             "with a map/package that exists in the client project if the "
             "client refreshes after Welcome\n");
    }
  }

  std::unordered_map<UdpClientKey, Session, UdpClientKeyHash> sessions;
  uint8_t buf[4096];

  while (g_running) {
    sockaddr_in from{};
    udp_ssize_t n = udp_recv(fd, from, buf, sizeof(buf));
    if (n < 0) {
      if (udp_recv_error_is_transient())
        continue;
      if (udp_recv_error_is_connection_reset()) {
        // Benign on Windows UDP when the client exits or the OS reports
        // ICMP Port Unreachable. Keep the endpoint alive for the next run.
        if (verbose_packets) {
          fprintf(stderr, "recvfrom ignored benign UDP reset: %s\n",
                  udp_last_error_string());
        }
        continue;
      }
      fprintf(stderr, "recvfrom failed: %s\n", udp_last_error_string());
      break;
    }

    UdpClientKey ck = udp_key_from_addr(from);
    std::string who = udp_addr_to_string(from);
    uint64_t ts = now_seconds();

    if (binlog) {
      udp_write_binlog_record(binlog, true, ts, from, buf, (uint32_t)n);
    }

    if (verbose_packets) {
      printf("rx %lld bytes from %s: %s\n", (long long)n, who.c_str(),
             udp_hex(buf, (size_t)n, 96).c_str());
    }

    ue574::ParsedPacket pp = ue574::parse_datagram(from, buf, (size_t)n);

    switch (pp.kind) {
    case ue574::PacketKind::UEHandshakeInitial: {
      print_handshake_summary(pp.handshake);
      printf("  real UE5.7.4-ish: Initial -> Challenge\n");
      auto out = ue574::build_ue574_challenge(from, pp.handshake);
      udp_send_logged(fd, from, out.data(), out.size(), binlog);
      break;
    }

    case ue574::PacketKind::UEHandshakeResponse: {
      print_handshake_summary(pp.handshake);
      bool ok = ue574::validate_ue574_response(from, pp.handshake);
      printf("  real UE5.7.4-ish: Response cookie validation: %s\n",
             ok ? "ok" : "FAIL");
      if (!ok)
        break;

      Session sess{};
      sess.phase = ue574::SessionPhase::CookieValidated;
      sess.created = ts;
      sess.last_seen = ts;
      sess.real_ue = true;
      sess.handshake = pp.handshake;
      ue574::extract_sequences_from_cookie(pp.handshake, sess.server_sequence,
                                           sess.client_sequence);
      sess.last_client_packet_seq = sess.client_sequence;

      // PacketNotify outgoing sequence space is seeded by the
      // StatelessConnect cookie. v14 accidentally left this at 0,
      // causing post-handshake replies to be sent as seq=0/1 even
      // though the server seed was 33. Start from the server seed so
      // NMT_Challenge uses seq=33 and NMT_Welcome uses seq=34.
      sess.next_server_packet_seq = sess.server_sequence;

      // UE initializes reliable channel sequence state from the same
      // StatelessConnect outgoing packet seed:
      //   InitOutReliable = OutgoingSequence & (MAX_CHSEQUENCE - 1)
      // and UChannel::PrepBunch sends ++OutReliable[ChIndex].
      // Therefore the first reliable control-channel bunch after
      // handshake should use (server_sequence + 1) & 1023, not 1.
      sess.next_out_reliable_ch0 =
          (uint16_t)((sess.server_sequence + 1) & 1023);
      sess.next_out_reliable_actor =
          (uint16_t)((sess.server_sequence + 1) & 1023);
      sess.next_out_reliable_datastream =
          (uint16_t)((sess.server_sequence + 1) & 1023);

      sessions[ck] = sess;
      printf("  sequence seeds: server=%u client=%u first_chseq=%u\n",
             (unsigned)sess.server_sequence, (unsigned)sess.client_sequence,
             (unsigned)sess.next_out_reliable_ch0);

      auto out = ue574::build_ue574_ack(pp.handshake);
      udp_send_logged(fd, from, out.data(), out.size(), binlog);
      printf("  sent Ack; next packets should be normal "
             "NetConnection/control-channel data\n");
      break;
    }

    case ue574::PacketKind::UEHandshakeOther: {
      print_handshake_summary(pp.handshake);
      printf("  recognized UE handshake packet but not Initial/Response; "
             "ignoring for now\n");
      break;
    }

    case ue574::PacketKind::TempHandshakeInitial: {
      printf("  temp harness: initial -> challenge\n");
      auto out = ue574::build_temp_handshake_challenge(from);
      udp_send_logged(fd, from, out.data(), out.size(), binlog);
      break;
    }

    case ue574::PacketKind::TempHandshakeResponse: {
      bool ok = ue574::validate_temp_handshake_response(from, buf, (size_t)n);
      printf("  temp harness: cookie validation: %s\n", ok ? "ok" : "FAIL");
      if (!ok)
        break;

      Session sess{};
      sess.phase = ue574::SessionPhase::CookieValidated;
      sess.created = ts;
      sess.last_seen = ts;
      sess.real_ue = false;
      sessions[ck] = sess;

      auto out = ue574::build_temp_handshake_ok();
      udp_send_logged(fd, from, out.data(), out.size(), binlog);
      break;
    }

    case ue574::PacketKind::TempControlHello: {
      auto it = sessions.find(ck);
      if (it == sessions.end()) {
        printf("  ignoring control hello: no validated cookie/session\n");
        break;
      }

      it->second.phase = ue574::SessionPhase::SawHello;
      it->second.last_seen = ts;

      printf("  temp harness: fake NMT_Hello -> fake NMT_Challenge\n");
      auto out = ue574::build_temp_control_challenge();
      udp_send_logged(fd, from, out.data(), out.size(), binlog);
      break;
    }

    case ue574::PacketKind::TempControlLogin: {
      auto it = sessions.find(ck);
      if (it == sessions.end()) {
        printf("  ignoring control login: no validated cookie/session\n");
        break;
      }

      it->second.phase = ue574::SessionPhase::Welcomed;
      it->second.last_seen = ts;

      printf("  temp harness: fake NMT_Login -> fake NMT_Welcome\n");
      auto out = ue574::build_temp_welcome();
      udp_send_logged(fd, from, out.data(), out.size(), binlog);
      break;
    }

    case ue574::PacketKind::ProbablyUEPostHandshakeDatagram: {
      auto it = sessions.find(ck);
      if (it != sessions.end()) {
        it->second.last_seen = ts;
        if (verbose_packets) {
          printf("  likely UE post-handshake datagram for validated session "
                 "phase=%s\n",
                 ue574::session_phase_name(it->second.phase));
        }
        ue574::PacketNotifyHeaderMini pn =
            ue574::parse_packet_notify_after_stateless_prefix(buf, (size_t)n);
        if (pn.ok) {
          it->second.last_client_packet_seq = pn.seq;
          it->second.max_client_seq_seen = pn.seq;
          it->second.max_client_acked_seen = pn.acked_seq;
          if (verbose_packets) {
            printf(
                "  packet notify: seq=%u acked=%u history_words=%u bits=%u\n",
                (unsigned)pn.seq, (unsigned)pn.acked_seq,
                (unsigned)pn.history_word_count, (unsigned)pn.bits_consumed);
          }
        }

        ue574::PostHandshakeProbeReport report =
            ue574::probe_post_handshake_packet(buf, (size_t)n);
        if (verbose_packets) {
          printf("%s", ue574::format_post_handshake_report(report).c_str());
        }

        ue574::PostHandshakeProbeReport exact_report{};
        const ue574::BunchProbe *exact = nullptr;
        if (pn.ok) {
          exact_report = ue574::probe_post_handshake_packet_from_bit(
              buf, (size_t)n, pn.bits_consumed);
          exact = first_exact_control_candidate(exact_report);
          if (exact) {
            if (verbose_packets)
              printf(
                  "  exact post-PacketNotify bunch: start_bit=%u "
                  "header_bits=%u data_bits=%u control=%u open=%u close=%u "
                  "reliable=%u partial=%u ch=%u chseq=%u first=0x%02x(%s) %s\n",
                  exact->start_bit, exact->header_bits, exact->data_bits,
                  exact->control ? 1u : 0u, exact->open ? 1u : 0u,
                  exact->close ? 1u : 0u, exact->reliable ? 1u : 0u,
                  exact->partial ? 1u : 0u, exact->channel_index,
                  exact->channel_sequence, exact->first_payload_byte,
                  ue574::control_message_name(exact->first_payload_byte),
                  exact->reason.c_str());
          } else if (it->second.phase == ue574::SessionPhase::Welcomed &&
                     verbose_packets) {
            printf("  exact post-PacketNotify bunch: none/ack-only at bit %u\n",
                   (unsigned)pn.bits_consumed);
          }
        }

        bool sent_server_packet_this_rx = false;
        bool saw_login_candidate = false;
        bool saw_hello = false;
        bool saw_exact_netspeed =
            exact && exact->first_payload_byte == ue574::NMT_Netspeed;
        bool saw_exact_join =
            exact && exact->first_payload_byte == ue574::NMT_Join;

        // v29 proved the broad offset scan is useful for hints but too noisy
        // for post-Welcome decisions. In the real v29 capture, the first
        // post-Welcome reliable control packets have the control-message
        // byte directly at pn.bits_consumed: 0x04 (NMT_NetSpeed), followed
        // by the serialized int32 net speed. Decode that exact byte before
        // trying to interpret the stream as a full bunch header.
        bool saw_direct_netspeed = false;
        bool saw_direct_join = false;
        bool saw_tail_join =
            (it->second.phase == ue574::SessionPhase::Welcomed) &&
            has_post_welcome_join_tail(buf, (size_t)n);
        uint8_t direct_control_id = 0xff;
        uint32_t direct_netspeed = 0;
        if (pn.ok && read_u8_at_bit(buf, (size_t)n, pn.bits_consumed,
                                    direct_control_id)) {
          saw_direct_netspeed = direct_control_id == ue574::NMT_Netspeed;
          saw_direct_join = direct_control_id == ue574::NMT_Join;
          if (saw_direct_netspeed) {
            (void)read_u32_at_bit(buf, (size_t)n, pn.bits_consumed + 8,
                                  direct_netspeed);
          }
        }

        if (it->second.phase == ue574::SessionPhase::Welcomed && pn.ok &&
            direct_control_id != 0xff) {
          if (saw_direct_netspeed) {
            printf("  exact direct control payload: NMT_NetSpeed speed=%u at "
                   "bit %u\n",
                   (unsigned)direct_netspeed, (unsigned)pn.bits_consumed);
          } else if (saw_direct_join) {
            printf("  exact direct control payload: NMT_Join at bit %u\n",
                   (unsigned)pn.bits_consumed);
          } else if (direct_control_id == ue574::NMT_Login &&
                     !it->second.saw_direct_login_after_welcome) {
            it->second.saw_direct_login_after_welcome = true;
            it->second.first_direct_login_after_welcome_seq = pn.seq;
            printf("  post-Welcome exact direct NMT_Login-like payload at "
                   "client seq=%u; likely late join/retry/close-ish pressure, "
                   "not initial Login\n",
                   (unsigned)pn.seq);
          } else if (verbose_packets && (size_t)n >= 18 && (size_t)n <= 24 &&
                     direct_control_id <= 32) {
            printf(
                "  exact direct control payload: first=0x%02x(%s) at bit %u\n",
                (unsigned)direct_control_id,
                ue574::control_message_name(direct_control_id),
                (unsigned)pn.bits_consumed);
          }
        }

        if (it->second.phase == ue574::SessionPhase::Welcomed && pn.ok &&
            saw_tail_join && !it->second.saw_tail_join) {
          it->second.saw_tail_join = true;
          it->second.first_tail_join_client_seq = pn.seq;
          printf("  post-Welcome compact control tail: saw 00 09 03 at client "
                 "seq=%u; treating as NMT_Join-side signal\n",
                 (unsigned)pn.seq);
        }

        if (it->second.phase == ue574::SessionPhase::Welcomed && pn.ok &&
            it->second.sent_post_welcome_failure &&
            !it->second.saw_failure_received &&
            contains_ascii_token(buf, (size_t)n, "FailureReceived")) {
          it->second.saw_failure_received = true;
          it->second.first_failure_received_client_seq = pn.seq;
          printf("  client control response: FailureReceived at client seq=%u; "
                 "post-Welcome reliable NMT_Failure was accepted\n",
                 (unsigned)pn.seq);
        }

        if (it->second.phase == ue574::SessionPhase::Welcomed && pn.ok &&
            it->second.sent_empty_actor_probe &&
            !it->second.saw_bunch_wrong_channel_type &&
            contains_ascii_token(buf, (size_t)n, "BunchWrongChannelType")) {
          it->second.saw_bunch_wrong_channel_type = true;
          it->second.first_bunch_wrong_channel_type_seq = pn.seq;
          printf(
              "  client actor-channel response: BunchWrongChannelType at "
              "client seq=%u; actor channel-name/type encoding was rejected\n",
              (unsigned)pn.seq);
        }

        if (it->second.phase == ue574::SessionPhase::Welcomed && pn.ok &&
            it->second.sent_empty_actor_probe &&
            !it->second.saw_actor_channel_failure &&
            (direct_control_id == ue574::NMT_ActorChannelFailure ||
             contains_ascii_token(buf, (size_t)n, "ActorChannelFailure"))) {
          it->second.saw_actor_channel_failure = true;
          it->second.first_actor_channel_failure_seq = pn.seq;
          printf("  client actor-channel response: NMT_ActorChannelFailure-ish "
                 "at client seq=%u; actor channel opened but "
                 "SerializeNewActor/payload failed\n",
                 (unsigned)pn.seq);
        }

        if (it->second.phase == ue574::SessionPhase::Welcomed && pn.ok &&
            it->second.sent_empty_actor_probe &&
            it->second.actor_probe_packet_acked &&
            !it->second.saw_actor_probe_late_pressure && (size_t)n == 18) {
          it->second.saw_actor_probe_late_pressure = true;
          it->second.first_actor_probe_late_pressure_seq = pn.seq;
          printf("  actor probe follow-up: compact 18-byte pressure packet at "
                 "client seq=%u after actor ACK; likely waiting for "
                 "SerializeNewActor/NetGUID payload\n",
                 (unsigned)pn.seq);
        }

        if (it->second.phase == ue574::SessionPhase::Welcomed && pn.ok &&
            it->second.sent_datastream_open_probe &&
            !it->second.datastream_open_packet_acked &&
            it->second.last_datastream_open_packet_seq != 0 &&
            pn.acked_seq >= it->second.last_datastream_open_packet_seq) {
          it->second.datastream_open_packet_acked = true;
        }

        if (it->second.datastream_open_packet_acked &&
            !it->second.announced_datastream_open_packet_acked) {
          it->second.announced_datastream_open_packet_acked = true;
          printf("  DataStream open probe packet was ACKed by client (server "
                 "seq=%u, client acked=%u); channel 2 DataStream handshake "
                 "envelope reached UE processing\n",
                 (unsigned)it->second.last_datastream_open_packet_seq,
                 (unsigned)pn.acked_seq);
        }

        if (it->second.phase == ue574::SessionPhase::Welcomed && pn.ok &&
            it->second.sent_empty_actor_probe &&
            !it->second.actor_probe_packet_acked &&
            it->second.last_actor_probe_packet_seq != 0 &&
            pn.acked_seq >= it->second.last_actor_probe_packet_seq) {
          it->second.actor_probe_packet_acked = true;
        }

        if (it->second.actor_probe_packet_acked &&
            !it->second.announced_actor_probe_packet_acked) {
          it->second.announced_actor_probe_packet_acked = true;
          printf(
              "  actor probe packet was ACKed by client (server seq=%u, client "
              "acked=%u); packet framing/channel open reached UE processing\n",
              (unsigned)it->second.last_actor_probe_packet_seq,
              (unsigned)pn.acked_seq);
          printf("  if there is no BunchWrongChannelType after this, the next "
                 "blocker is actor payload / SerializeNewActor, not channel "
                 "type\n");
        }

        if (it->second.sent_actor_followup_probe &&
            !it->second.actor_followup_packet_acked &&
            it->second.last_actor_followup_packet_seq != 0 &&
            pn.acked_seq >= it->second.last_actor_followup_packet_seq) {
          it->second.actor_followup_packet_acked = true;
        }

        if (it->second.actor_followup_packet_acked &&
            !it->second.announced_actor_followup_packet_acked) {
          it->second.announced_actor_followup_packet_acked = true;
          printf("  actor follow-up content packet was ACKed by client (server "
                 "seq=%u, client acked=%u); content bunch envelope reached UE "
                 "processing\n",
                 (unsigned)it->second.last_actor_followup_packet_seq,
                 (unsigned)pn.acked_seq);
          printf("  if late pressure still follows, next blocker is real "
                 "PackageMap/SerializeNewActor data, not open-vs-content "
                 "timing\n");
        }

        bool saw_real_login_payload =
            looks_like_real_login_payload(buf, (size_t)n);

        // The current probe is deliberately broad and can find multiple
        // plausible candidates in the same packet. Tiny 10/11-byte ack packets
        // routinely contain false NMT_Login/NMT_Hello candidates, so do not let
        // those trigger NMT_Welcome. The real NMT_Login packet is URL-bearing
        // and much larger.
        for (const auto &cand : report.candidates) {
          if (cand.plausible && cand.first_payload_byte == ue574::NMT_Login) {
            saw_login_candidate = true;
          }
          if (cand.plausible && cand.first_payload_byte == ue574::NMT_Hello) {
            saw_hello = true;
          }
        }

        // Some UE login packets are URL-bearing/plain enough to spot by ASCII.
        // Others in the captures are large reliable control packets without
        // easy ASCII tokens at this stage, but they arrive immediately after
        // our NMT_Challenge and before Welcome. Treat those as real login
        // payloads too. Keep ignoring tiny ack-only packets that merely contain
        // accidental NMT_Login-looking bytes.
        bool saw_large_post_challenge_login_payload =
            it->second.sent_nmt_challenge && !it->second.sent_nmt_welcome &&
            n >= 96;

        bool saw_login = saw_real_login_payload ||
                         saw_large_post_challenge_login_payload ||
                         (saw_login_candidate && n >= 64);
        if (saw_real_login_payload) {
          printf("  observed real URL-bearing NMT_Login payload; prioritizing "
                 "over probe false positives\n");
        } else if (saw_large_post_challenge_login_payload) {
          printf("  observed large post-challenge control payload (%zu bytes); "
                 "treating as NMT_Login even without ASCII URL tokens\n",
                 (size_t)n);
        } else if (saw_login_candidate && n < 64) {
          if (verbose_packets)
            printf("  ignoring tiny false-positive NMT_Login candidate in "
                   "%zu-byte packet\n",
                   (size_t)n);
        }

        if (saw_login && it->second.sent_nmt_challenge) {
          if (it->second.phase == ue574::SessionPhase::Welcomed) {
            printf("  observed likely NMT_Login after NMT_Welcome; treating as "
                   "retransmit/noise, not regressing phase\n");
          } else {
            it->second.phase = ue574::SessionPhase::SawLogin;
            printf("  observed likely NMT_Login after NMT_Challenge; "
                   "experimental next step is NMT_Welcome bunch\n");
          }
          if (experimental_control_replies && it->second.real_ue) {
            if (!it->second.sent_nmt_welcome) {
              auto out = ue574::build_experimental_nmt_welcome_stateful_custom(
                  it->second.handshake, it->second.last_client_packet_seq,
                  it->second.next_server_packet_seq,
                  it->second.next_out_reliable_ch0, welcome_level_name,
                  welcome_game_name, welcome_redirect_url);
              printf("  sending experimental NMT_Welcome clean channel-0 reply "
                     "(%zu bytes seq=%u chseq=%u ack_client=%u)\n",
                     out.size(), (unsigned)it->second.next_server_packet_seq,
                     (unsigned)it->second.next_out_reliable_ch0,
                     (unsigned)it->second.last_client_packet_seq);
              udp_send_logged(fd, from, out.data(), out.size(), binlog);
              sent_server_packet_this_rx = true;
              it->second.last_welcome_packet_seq =
                  it->second.next_server_packet_seq;
              it->second.next_server_packet_seq =
                  (uint16_t)((it->second.next_server_packet_seq + 1) & 0x3fff);
              it->second.next_out_reliable_ch0 =
                  (uint16_t)((it->second.next_out_reliable_ch0 + 1) & 1023);
              it->second.sent_nmt_welcome = true;
              it->second.phase = ue574::SessionPhase::Welcomed;
            } else if (pn.ok && pn.acked_seq != 0 &&
                       pn.acked_seq < it->second.next_server_packet_seq) {
              // Retransmit only when the client has not acked the Welcome
              // packet yet. Once it has acked Welcome, later URL-bearing
              // traffic is the next login/join phase and should not cause us to
              // spam duplicate Welcome bunches.
              uint16_t resend_chseq =
                  (uint16_t)((it->second.next_out_reliable_ch0 + 1023) & 1023);
              auto out = ue574::build_experimental_nmt_welcome_stateful_custom(
                  it->second.handshake, it->second.last_client_packet_seq,
                  it->second.next_server_packet_seq, resend_chseq,
                  welcome_level_name, welcome_game_name, welcome_redirect_url);
              printf(
                  "  retransmitting unacked NMT_Welcome clean channel-0 reply "
                  "(%zu bytes seq=%u chseq=%u ack_client=%u client_acked=%u)\n",
                  out.size(), (unsigned)it->second.next_server_packet_seq,
                  (unsigned)resend_chseq,
                  (unsigned)it->second.last_client_packet_seq,
                  (unsigned)pn.acked_seq);
              udp_send_logged(fd, from, out.data(), out.size(), binlog);
              sent_server_packet_this_rx = true;
              it->second.last_welcome_packet_seq =
                  it->second.next_server_packet_seq;
              it->second.next_server_packet_seq =
                  (uint16_t)((it->second.next_server_packet_seq + 1) & 0x3fff);
              it->second.phase = ue574::SessionPhase::Welcomed;
            } else {
              printf("  Welcome already acked or no retransmit needed; holding "
                     "state for next join/actor-channel work\n");
            }
          }
        } else if (saw_hello) {
          // The broad probe finds false-positive NMT_Hello bytes
          // inside later packets. Do not regress the state machine
          // after Login/Welcome has already been observed.
          if (it->second.phase != ue574::SessionPhase::SawLogin &&
              it->second.phase != ue574::SessionPhase::Welcomed) {
            it->second.phase = ue574::SessionPhase::SawHello;
          }

          if (it->second.phase == ue574::SessionPhase::Welcomed) {
            if (verbose_packets)
              printf("  observed likely NMT_Hello false-positive after "
                     "NMT_Welcome; ignoring\n");
          } else if (it->second.phase == ue574::SessionPhase::SawLogin) {
            if (verbose_packets)
              printf("  observed likely NMT_Hello false-positive after "
                     "NMT_Login; ignoring\n");
          } else {
            printf("  observed likely NMT_Hello; experimental next step is "
                   "NMT_Challenge bunch\n");
          }

          if (experimental_control_replies && it->second.real_ue &&
              it->second.phase != ue574::SessionPhase::SawLogin &&
              it->second.phase != ue574::SessionPhase::Welcomed) {
            if (!it->second.sent_nmt_challenge) {
              auto out = ue574::build_experimental_nmt_challenge_stateful(
                  it->second.handshake, it->second.last_client_packet_seq,
                  it->second.next_server_packet_seq,
                  it->second.next_out_reliable_ch0);
              printf("  sending experimental NMT_Challenge clean channel-0 "
                     "reply (%zu bytes seq=%u chseq=%u ack_client=%u)\n",
                     out.size(), (unsigned)it->second.next_server_packet_seq,
                     (unsigned)it->second.next_out_reliable_ch0,
                     (unsigned)it->second.last_client_packet_seq);
              udp_send_logged(fd, from, out.data(), out.size(), binlog);
              sent_server_packet_this_rx = true;
              it->second.next_server_packet_seq =
                  (uint16_t)((it->second.next_server_packet_seq + 1) & 0x3fff);
              it->second.next_out_reliable_ch0 =
                  (uint16_t)((it->second.next_out_reliable_ch0 + 1) & 1023);
              it->second.sent_nmt_challenge = true;
            } else {
              printf("  NMT_Challenge already sent for this session; not "
                     "retransmitting on probe packet\n");
            }
          }
        } else if (saw_login) {
          if (verbose_packets)
            printf("  saw a possible NMT_Login candidate before NMT_Challenge "
                   "was marked sent; ignoring for now\n");
        }

        if (it->second.phase == ue574::SessionPhase::Welcomed && pn.ok) {
          if (pn.acked_seq == it->second.last_welcome_packet_seq &&
              !it->second.announced_post_welcome_ack_loop) {
            printf("  client has ACKed NMT_Welcome seq=%u; entering "
                   "post-Welcome map/join phase\n",
                   (unsigned)it->second.last_welcome_packet_seq);
            it->second.announced_post_welcome_ack_loop = true;
          }

          it->second.post_welcome_client_packets++;

          if ((saw_exact_netspeed || saw_direct_netspeed) &&
              !it->second.saw_exact_netspeed) {
            it->second.saw_exact_netspeed = true;
            it->second.saw_direct_netspeed = saw_direct_netspeed;
            printf("  post-Welcome control: NMT_NetSpeed observed%s; "
                   "CurrentNetSpeed=%u\n",
                   saw_direct_netspeed ? " by exact direct payload"
                                       : " by exact bunch probe",
                   (unsigned)direct_netspeed);
          }
          if ((saw_exact_join || saw_direct_join || saw_tail_join) &&
              !it->second.saw_exact_join) {
            it->second.saw_exact_join = true;
            it->second.saw_direct_join = saw_direct_join;
            it->second.first_exact_join_client_seq = pn.seq;
            it->second.first_direct_join_client_seq =
                saw_direct_join ? pn.seq : 0;
            printf("  post-Welcome control: NMT_Join observed at client "
                   "seq=%u%s; next required milestone is SpawnPlayActor / "
                   "actor-channel replication\n",
                   (unsigned)pn.seq,
                   saw_direct_join
                       ? " by exact direct payload"
                       : (saw_tail_join ? " by compact 00 09 03 tail"
                                        : " by exact bunch probe"));
            printf(
                "  join/player hook: GameMode='%s' is selected; future code "
                "should create PlayerController/Pawn and replicate them now\n",
                welcome_game_name.c_str());
            if (!planned_player_controller_class.empty() ||
                !planned_pawn_class.empty()) {
              printf("  planned classes: PlayerController='%s' Pawn='%s'\n",
                     planned_player_controller_class.c_str(),
                     planned_pawn_class.c_str());
            }
          }

          if (it->second.saw_exact_netspeed && !it->second.saw_exact_join &&
              it->second.post_welcome_client_packets >= 8 &&
              !it->second.announced_waiting_for_actor_replication) {
            it->second.announced_waiting_for_actor_replication = true;
            printf("  post-Welcome state: NetSpeed is decoded and ACKed, but "
                   "no exact NMT_Join payload arrived yet; client is now "
                   "waiting for real server world/player replication\n");
            printf(
                "  next implementation step: synthesize SpawnPlayActor result "
                "and first actor-channel bunch for PlayerController/Pawn, not "
                "more Welcome/GameMode strings\n");
          }

          if ((size_t)n == 10) {
            if (verbose_packets)
              printf("  post-Welcome small ACK/keepalive from client\n");
          } else if ((size_t)n >= 20 && (size_t)n <= 24) {
            if (verbose_packets)
              printf("  post-Welcome small reliable control packet; likely "
                     "NMT_NetSpeed or early join/map traffic\n");
          } else if ((size_t)n == 18) {
            if (verbose_packets)
              printf("  post-Welcome compact reliable control packet; likely "
                     "join/close-ish follow-up\n");
          }
        }

        // Optional v49 probe: UE5.7 Iris creates static channel 2 as
        // DataStream. Before trying actor channels, send the same zero-payload
        // reliable DataStream handshake bunch that
        // UDataStreamChannel::SendOpenBunch emits.
        if (experimental_control_replies && post_join_datastream_open_probe &&
            it->second.real_ue &&
            it->second.phase == ue574::SessionPhase::Welcomed &&
            it->second.sent_nmt_welcome &&
            !it->second.sent_datastream_open_probe &&
            !sent_server_packet_this_rx && pn.ok && it->second.saw_exact_join &&
            it->second.post_welcome_client_packets >=
                post_join_datastream_open_after &&
            pn.acked_seq >= it->second.last_welcome_packet_seq) {

          // v52: use the actual UE channel index by default. v51 proved the
          // logical<<1 calibration was wrong: wire 4 still decoded into the
          // Voice-channel path. Use channel 2 for the existing DataStream
          // channel, and keep --post-join-datastream-wire-channel as an
          // explicit raw override for future A/B tests.
          const uint16_t datastream_wire_ch =
              post_join_datastream_wire_channel
                  ? post_join_datastream_wire_channel
                  : post_join_datastream_channel;
          auto out = ue574::build_experimental_datastream_open_probe(
              it->second.handshake, it->second.last_client_packet_seq,
              it->second.next_server_packet_seq, datastream_wire_ch,
              it->second.next_out_reliable_datastream,
              post_join_datastream_header_mode);
          printf("  sending experimental DataStream open probe after Join (%zu "
                 "bytes seq=%u logical-ch=%u wire-ch=%u chseq=%u ack_client=%u "
                 "name=DataStream zero-payload header-mode=%s)\n",
                 out.size(), (unsigned)it->second.next_server_packet_seq,
                 (unsigned)post_join_datastream_channel,
                 (unsigned)datastream_wire_ch,
                 (unsigned)it->second.next_out_reliable_datastream,
                 (unsigned)it->second.last_client_packet_seq,
                 ue574::datastream_header_mode_name(
                     post_join_datastream_header_mode));
          printf("  DataStream note: this tests Iris channel-2 handshake, not "
                 "classic actor-channel replication\n");
          udp_send_logged(fd, from, out.data(), out.size(), binlog);
          it->second.last_datastream_open_packet_seq =
              it->second.next_server_packet_seq;
          it->second.next_server_packet_seq =
              (uint16_t)((it->second.next_server_packet_seq + 1) & 0x3fff);
          it->second.next_out_reliable_datastream =
              (uint16_t)((it->second.next_out_reliable_datastream + 1) & 1023);
          it->second.sent_datastream_open_probe = true;
          sent_server_packet_this_rx = true;
        }

        // Optional v35 probe: once we have a Join-side signal, send the
        // smallest possible reliable Actor-channel open bunch. This is not a
        // valid PlayerController/Pawn replication payload yet; it is a
        // controlled probe to learn whether the client accepts our non-control
        // channel header shape before we implement PackageMap/NetGUID/actor
        // state.
        if (experimental_control_replies && post_join_empty_actor_probe &&
            it->second.real_ue &&
            it->second.phase == ue574::SessionPhase::Welcomed &&
            it->second.sent_nmt_welcome && !it->second.sent_empty_actor_probe &&
            !sent_server_packet_this_rx && pn.ok && it->second.saw_exact_join &&
            it->second.post_welcome_client_packets >=
                post_join_actor_probe_after &&
            pn.acked_seq >= it->second.last_welcome_packet_seq) {

          auto out = ue574::build_experimental_empty_actor_channel_open_probe(
              it->second.handshake, it->second.last_client_packet_seq,
              it->second.next_server_packet_seq, post_join_actor_channel,
              it->second.next_out_reliable_actor, post_join_actor_name_mode,
              post_join_actor_payload_mode,
              planned_player_controller_class.empty()
                  ? std::string("/Script/Engine.PlayerController")
                  : planned_player_controller_class);
          printf("  sending experimental Actor-channel open probe (%zu bytes "
                 "seq=%u ch=%u chseq=%u ack_client=%u name-mode=%s "
                 "payload-mode=%s)\n",
                 out.size(), (unsigned)it->second.next_server_packet_seq,
                 (unsigned)post_join_actor_channel,
                 (unsigned)it->second.next_out_reliable_actor,
                 (unsigned)it->second.last_client_packet_seq,
                 ue574::actor_channel_name_wire_mode_name(
                     post_join_actor_name_mode),
                 ue574::actor_payload_probe_mode_name(
                     post_join_actor_payload_mode));
          printf(
              "  actor probe note: this is still a SerializeNewActor payload "
              "probe, not real PlayerController/Pawn replication yet\n");
          udp_send_logged(fd, from, out.data(), out.size(), binlog);
          it->second.last_actor_probe_packet_seq =
              it->second.next_server_packet_seq;
          it->second.next_server_packet_seq =
              (uint16_t)((it->second.next_server_packet_seq + 1) & 0x3fff);
          it->second.next_out_reliable_actor =
              (uint16_t)((it->second.next_out_reliable_actor + 1) & 1023);
          it->second.sent_empty_actor_probe = true;
          sent_server_packet_this_rx = true;
        }

        // Optional v45 probe: after the actor-channel open has been ACKed,
        // send a second reliable actor-channel content bunch on the same
        // channel. This tests whether the pending client is waiting for
        // follow-up actor content after the open bunch, versus requiring a
        // complete SerializeNewActor payload in the open bunch itself.
        if (experimental_control_replies && post_join_actor_followup_probe &&
            it->second.real_ue &&
            it->second.phase == ue574::SessionPhase::Welcomed &&
            it->second.sent_empty_actor_probe &&
            it->second.actor_probe_packet_acked &&
            !it->second.sent_actor_followup_probe &&
            !sent_server_packet_this_rx && pn.ok &&
            it->second.post_welcome_client_packets >=
                post_join_actor_followup_after &&
            pn.acked_seq >= it->second.last_actor_probe_packet_seq) {

          auto out = ue574::build_experimental_actor_channel_content_probe(
              it->second.handshake, it->second.last_client_packet_seq,
              it->second.next_server_packet_seq, post_join_actor_channel,
              it->second.next_out_reliable_actor, post_join_actor_name_mode,
              post_join_actor_payload_mode,
              planned_player_controller_class.empty()
                  ? std::string("/Script/Engine.PlayerController")
                  : planned_player_controller_class);
          printf("  sending experimental Actor-channel follow-up content probe "
                 "(%zu bytes seq=%u ch=%u chseq=%u ack_client=%u name-mode=%s "
                 "payload-mode=%s)\n",
                 out.size(), (unsigned)it->second.next_server_packet_seq,
                 (unsigned)post_join_actor_channel,
                 (unsigned)it->second.next_out_reliable_actor,
                 (unsigned)it->second.last_client_packet_seq,
                 ue574::actor_channel_name_wire_mode_name(
                     post_join_actor_name_mode),
                 ue574::actor_payload_probe_mode_name(
                     post_join_actor_payload_mode));
          printf(
              "  actor follow-up note: second reliable actor bunch after open; "
              "diagnostic only, still not real PlayerController replication\n");
          udp_send_logged(fd, from, out.data(), out.size(), binlog);
          it->second.last_actor_followup_packet_seq =
              it->second.next_server_packet_seq;
          it->second.next_server_packet_seq =
              (uint16_t)((it->second.next_server_packet_seq + 1) & 0x3fff);
          it->second.next_out_reliable_actor =
              (uint16_t)((it->second.next_out_reliable_actor + 1) & 1023);
          it->second.sent_actor_followup_probe = true;
          sent_server_packet_this_rx = true;
        }

        // Optional v33 diagnostic: once NetSpeed is proven and the client has
        // sent a few post-Welcome packets without a decodable Join/actor path,
        // send a real reliable control-channel NMT_Failure. This is
        // intentionally not actor replication; it is a controlled proof that
        // post-Welcome reliable server->client control messages are still
        // accepted after Welcome.
        if (experimental_control_replies && post_welcome_failure_after > 0 &&
            it->second.real_ue &&
            it->second.phase == ue574::SessionPhase::Welcomed &&
            it->second.sent_nmt_welcome &&
            !it->second.sent_post_welcome_failure &&
            !sent_server_packet_this_rx && pn.ok &&
            it->second.saw_exact_netspeed && !it->second.saw_exact_join &&
            it->second.post_welcome_client_packets >=
                post_welcome_failure_after &&
            pn.acked_seq >= it->second.last_welcome_packet_seq) {

          auto out = ue574::build_experimental_nmt_failure_stateful_custom(
              it->second.handshake, it->second.last_client_packet_seq,
              it->second.next_server_packet_seq,
              it->second.next_out_reliable_ch0, post_welcome_failure_text);
          printf("  sending diagnostic post-Welcome NMT_Failure (%zu bytes "
                 "seq=%u chseq=%u ack_client=%u): %s\n",
                 out.size(), (unsigned)it->second.next_server_packet_seq,
                 (unsigned)it->second.next_out_reliable_ch0,
                 (unsigned)it->second.last_client_packet_seq,
                 post_welcome_failure_text.c_str());
          udp_send_logged(fd, from, out.data(), out.size(), binlog);
          it->second.last_failure_packet_seq =
              it->second.next_server_packet_seq;
          it->second.next_server_packet_seq =
              (uint16_t)((it->second.next_server_packet_seq + 1) & 0x3fff);
          it->second.next_out_reliable_ch0 =
              (uint16_t)((it->second.next_out_reliable_ch0 + 1) & 1023);
          it->second.sent_post_welcome_failure = true;
          sent_server_packet_this_rx = true;
        }

        // After Welcome, the client sends NetSpeed and then join/close-ish
        // traffic. v28-v31 answered every client packet with a fresh ACK-only
        // server packet. That proves the packet/session layer is solid, but it
        // also creates an artificial ACK ping-pong: each ACK-only packet is a
        // new reliable PacketNotify sequence the client then ACKs back.
        //
        // v32 paces those ACK-only packets. We still ACK often enough to keep
        // the connection from timing out, but we no longer manufacture hundreds
        // of new server packet IDs per second while no real world/actor data
        // exists. This makes the next missing feature easier to see.
        if (experimental_control_replies && it->second.real_ue &&
            it->second.phase == ue574::SessionPhase::Welcomed &&
            it->second.sent_nmt_welcome && !sent_server_packet_this_rx &&
            pn.ok && pn.acked_seq >= it->second.last_welcome_packet_seq &&
            pn.seq != it->second.last_ack_only_client_seq) {

          const bool under_cap =
              (post_welcome_max_ack_only == 0 ||
               it->second.ack_only_packets_sent < post_welcome_max_ack_only);
          const bool ack_disabled = (post_welcome_ack_every == 0);
          const bool bootstrap_ack = it->second.ack_only_packets_sent < 3;
          const bool interval_ack = (post_welcome_ack_every > 0 &&
                                     (it->second.post_welcome_client_packets %
                                      post_welcome_ack_every) == 0);
          const bool event_ack = saw_exact_netspeed || saw_direct_netspeed ||
                                 saw_exact_join || saw_direct_join ||
                                 saw_tail_join;
          const bool should_send_ack_only =
              under_cap && !ack_disabled &&
              (bootstrap_ack || interval_ack || event_ack);

          if (should_send_ack_only) {
            auto out = ue574::build_experimental_ack_only_packet(
                it->second.handshake, it->second.last_client_packet_seq,
                it->second.next_server_packet_seq);
            it->second.ack_only_packets_sent++;
            if (verbose_packets || it->second.ack_only_packets_sent <= 3 ||
                (it->second.ack_only_packets_sent % 25u) == 0u) {
              printf(
                  "  paced ACK-only post-Welcome keepalive #%u (%zu bytes "
                  "server_seq=%u ack_client=%u client_acked=%u interval=%u)\n",
                  (unsigned)it->second.ack_only_packets_sent, out.size(),
                  (unsigned)it->second.next_server_packet_seq,
                  (unsigned)it->second.last_client_packet_seq,
                  (unsigned)pn.acked_seq, (unsigned)post_welcome_ack_every);
            }
            udp_send_logged(fd, from, out.data(), out.size(), binlog);
            it->second.last_ack_only_client_seq = pn.seq;
            it->second.next_server_packet_seq =
                (uint16_t)((it->second.next_server_packet_seq + 1) & 0x3fff);
          } else if (verbose_packets) {
            printf("  paced post-Welcome: not sending ACK-only on client "
                   "seq=%u post_count=%u ack_sent=%u%s%s\n",
                   (unsigned)pn.seq,
                   (unsigned)it->second.post_welcome_client_packets,
                   (unsigned)it->second.ack_only_packets_sent,
                   ack_disabled ? " disabled" : "",
                   !under_cap ? " cap-reached" : "");
          }
        }
      } else {
        printf(
            "  likely UE binary datagram before local session is validated\n");
      }
      break;
    }

    case ue574::PacketKind::Unknown:
    default: {
      auto it = sessions.find(ck);
      if (it != sessions.end()) {
        it->second.last_seen = ts;
        printf("  validated session phase=%s; unknown payload\n",
               ue574::session_phase_name(it->second.phase));
      } else {
        printf("  unknown packet before validation\n");
      }
      break;
    }
    }
  }

  printf("session summary:\n");
  for (const auto &kv : sessions) {
    const Session &sess = kv.second;
    printf(
        "  phase=%s server_next=%u last_client_seq=%u client_acked=%u "
        "ack_only_sent=%u NetSpeed=%s Join=%s DataStreamProbe=%s "
        "DataStreamAck=%s ActorProbe=%s ActorAck=%s ActorFollowup=%s "
        "ActorFollowupAck=%s ActorChannelFailure=%s ActorLatePressure=%s "
        "BunchWrongType=%s Failure=%s FailureReceived=%s lateDirectLogin=%s\n",
        ue574::session_phase_name(sess.phase),
        (unsigned)sess.next_server_packet_seq,
        (unsigned)sess.max_client_seq_seen,
        (unsigned)sess.max_client_acked_seen,
        (unsigned)sess.ack_only_packets_sent,
        sess.saw_exact_netspeed ? "yes" : "no",
        sess.saw_exact_join ? "yes" : "no",
        sess.sent_datastream_open_probe ? "yes" : "no",
        sess.datastream_open_packet_acked ? "yes" : "no",
        sess.sent_empty_actor_probe ? "yes" : "no",
        sess.actor_probe_packet_acked ? "yes" : "no",
        sess.sent_actor_followup_probe ? "yes" : "no",
        sess.actor_followup_packet_acked ? "yes" : "no",
        sess.saw_actor_channel_failure ? "yes" : "no",
        sess.saw_actor_probe_late_pressure ? "yes" : "no",
        sess.saw_bunch_wrong_channel_type ? "yes" : "no",
        sess.sent_post_welcome_failure ? "yes" : "no",
        sess.saw_failure_received ? "yes" : "no",
        sess.saw_direct_login_after_welcome ? "yes" : "no");
  }

  if (binlog)
    fclose(binlog);
  udp_close(fd);
  return 0;
}
