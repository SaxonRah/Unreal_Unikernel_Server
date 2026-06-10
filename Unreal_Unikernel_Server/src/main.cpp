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
  bool sent_nmt_challenge = false;
  bool sent_nmt_welcome = false;
  uint16_t last_welcome_packet_seq = 0;
  uint16_t last_ack_only_client_seq = 0;
};

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
  std::string welcome_level_name = "/Game/Maps/Minimal";
  std::string welcome_game_name = "/Script/Engine.GameModeBase";
  std::string welcome_redirect_url = "";

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
    } else if (!strcmp(argv[i], "--level-name") && i + 1 < argc) {
      welcome_level_name = argv[++i];
    } else if (!strcmp(argv[i], "--game-name") && i + 1 < argc) {
      welcome_game_name = argv[++i];
    } else if (!strcmp(argv[i], "--redirect-url") && i + 1 < argc) {
      welcome_redirect_url = argv[++i];
    } else {
      fprintf(
          stderr,
          "usage: %s [--port 7777] [--binlog packets.binlog] "
          "[--experimental-control-replies] [--level-name /Game/Maps/Map] "
          "[--game-name /Script/Engine.GameModeBase] [--redirect-url URL]\n",
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
  printf("note: after Ack, this scans likely control-channel bunches; optional "
         "experimental replies need PackageMap/CoreNet verification\n");
  printf("experimental control replies: %s\n",
         experimental_control_replies ? "enabled" : "disabled");
  if (experimental_control_replies) {
    printf("welcome payload: LevelName='%s' GameName='%s' RedirectURL='%s'\n",
           welcome_level_name.c_str(), welcome_game_name.c_str(),
           welcome_redirect_url.c_str());
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
      if (errno == EINTR)
        continue;
      fprintf(stderr, "recvfrom failed: %s\n", strerror(errno));
      break;
    }

    UdpClientKey ck = udp_key_from_addr(from);
    std::string who = udp_addr_to_string(from);
    uint64_t ts = now_seconds();

    if (binlog) {
      udp_write_binlog_record(binlog, true, ts, from, buf, (uint32_t)n);
    }

    printf("rx %lld bytes from %s: %s\n", (long long)n, who.c_str(),
           udp_hex(buf, (size_t)n, 96).c_str());

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
        printf("  likely UE post-handshake datagram for validated session "
               "phase=%s\n",
               ue574::session_phase_name(it->second.phase));
        ue574::PacketNotifyHeaderMini pn =
            ue574::parse_packet_notify_after_stateless_prefix(buf, (size_t)n);
        if (pn.ok) {
          it->second.last_client_packet_seq = pn.seq;
          printf("  packet notify: seq=%u acked=%u history_words=%u bits=%u\n",
                 (unsigned)pn.seq, (unsigned)pn.acked_seq,
                 (unsigned)pn.history_word_count, (unsigned)pn.bits_consumed);
        }

        ue574::PostHandshakeProbeReport report =
            ue574::probe_post_handshake_packet(buf, (size_t)n);
        printf("%s", ue574::format_post_handshake_report(report).c_str());

        bool sent_server_packet_this_rx = false;
        bool saw_login_candidate = false;
        bool saw_hello = false;
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
            printf("  observed likely NMT_Hello false-positive after "
                   "NMT_Welcome; ignoring\n");
          } else if (it->second.phase == ue574::SessionPhase::SawLogin) {
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
          printf("  saw a possible NMT_Login candidate before NMT_Challenge "
                 "was marked sent; ignoring for now\n");
        }

        if (it->second.phase == ue574::SessionPhase::Welcomed && pn.ok) {
          if (pn.acked_seq == it->second.last_welcome_packet_seq) {
            printf("  client has ACKed NMT_Welcome seq=%u; now in post-Welcome "
                   "map/join phase\n",
                   (unsigned)it->second.last_welcome_packet_seq);
          }
          if ((size_t)n == 10) {
            printf("  post-Welcome small ACK/keepalive from client\n");
          } else if ((size_t)n >= 20 && (size_t)n <= 24) {
            printf("  post-Welcome small reliable control packet; likely "
                   "NMT_NetSpeed or early join/map traffic\n");
          } else if ((size_t)n == 18) {
            printf("  post-Welcome compact reliable control packet; likely "
                   "join/close-ish follow-up\n");
          }
        }

        // After Welcome, the client sends NetSpeed and then join/close-ish
        // reliable control traffic. Because this prototype has no actor/world
        // replication packets yet, it would otherwise stay silent and never
        // PacketNotify-ACK those client packets. Send a tiny ACK-only packet
        // once the client has ACKed our Welcome so it stops retransmitting and
        // we can observe the next real protocol requirement instead of timeout
        // refreshes.
        if (experimental_control_replies && it->second.real_ue &&
            it->second.phase == ue574::SessionPhase::Welcomed &&
            it->second.sent_nmt_welcome && !sent_server_packet_this_rx &&
            pn.ok && pn.acked_seq >= it->second.last_welcome_packet_seq &&
            pn.seq != it->second.last_ack_only_client_seq) {
          // v26/v27 only sent ACK-only packets while the client's
          // PacketNotify ack was exactly the Welcome packet. The real
          // client then ACKs our ACK-only server packets too, so its
          // ack value advances to 35/36/etc.  Keep sending ACK-only
          // responses for new post-Welcome client packets as long as
          // the client has acknowledged at least the Welcome packet.
          // This keeps PacketNotify alive while we work out the first
          // real post-Welcome world/channel response.
          auto out = ue574::build_experimental_ack_only_packet(
              it->second.handshake, it->second.last_client_packet_seq,
              it->second.next_server_packet_seq);
          printf("  sending continuous post-Welcome ACK-only packet (%zu bytes "
                 "seq=%u ack_client=%u client_acked=%u welcome_seq=%u)\n",
                 out.size(), (unsigned)it->second.next_server_packet_seq,
                 (unsigned)it->second.last_client_packet_seq,
                 (unsigned)pn.acked_seq,
                 (unsigned)it->second.last_welcome_packet_seq);
          udp_send_logged(fd, from, out.data(), out.size(), binlog);
          it->second.last_ack_only_client_seq = pn.seq;
          it->second.next_server_packet_seq =
              (uint16_t)((it->second.next_server_packet_seq + 1) & 0x3fff);
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

  if (binlog)
    fclose(binlog);
  udp_close(fd);
  return 0;
}
