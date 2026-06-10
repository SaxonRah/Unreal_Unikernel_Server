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
  uint16_t next_out_reliable_ch0 = 1;
  bool sent_nmt_challenge = false;
  bool sent_nmt_welcome = false;
};

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
    } else {
      fprintf(stderr,
              "usage: %s [--port 7777] [--binlog packets.binlog] "
              "[--experimental-control-replies]\n",
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
      sessions[ck] = sess;
      printf("  sequence seeds: server=%u client=%u\n",
             (unsigned)sess.server_sequence, (unsigned)sess.client_sequence);

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

        bool saw_login = false;
        bool saw_hello = false;

        // The current probe is deliberately broad and can find multiple
        // plausible candidates in the same packet. After NMT_Challenge is sent,
        // NMT_Login is more important than another false-positive NMT_Hello, so
        // detect all candidates first and then prioritize by current login
        // phase.
        for (const auto &cand : report.candidates) {
          if (cand.plausible && cand.first_payload_byte == ue574::NMT_Login) {
            saw_login = true;
          }
          if (cand.plausible && cand.first_payload_byte == ue574::NMT_Hello) {
            saw_hello = true;
          }
        }

        if (saw_login && it->second.sent_nmt_challenge) {
          it->second.phase = ue574::SessionPhase::SawLogin;
          printf("  observed likely NMT_Login after NMT_Challenge; "
                 "experimental next step is NMT_Welcome bunch\n");
          if (experimental_control_replies && it->second.real_ue) {
            if (!it->second.sent_nmt_welcome) {
              auto out = ue574::build_experimental_nmt_welcome_stateful(
                  it->second.handshake, it->second.last_client_packet_seq,
                  it->second.next_server_packet_seq,
                  it->second.next_out_reliable_ch0);
              printf("  sending experimental NMT_Welcome clean channel-0 reply "
                     "(%zu bytes seq=%u chseq=%u ack_client=%u)\n",
                     out.size(), (unsigned)it->second.next_server_packet_seq,
                     (unsigned)it->second.next_out_reliable_ch0,
                     (unsigned)it->second.last_client_packet_seq);
              udp_send_logged(fd, from, out.data(), out.size(), binlog);
              it->second.next_server_packet_seq =
                  (uint16_t)((it->second.next_server_packet_seq + 1) & 0x3fff);
              it->second.next_out_reliable_ch0 =
                  (uint16_t)((it->second.next_out_reliable_ch0 + 1) & 1023);
              it->second.sent_nmt_welcome = true;
              it->second.phase = ue574::SessionPhase::Welcomed;
            } else {
              printf("  NMT_Welcome already sent for this session; not "
                     "retransmitting on probe packet\n");
            }
          }
        } else if (saw_hello) {
          it->second.phase = ue574::SessionPhase::SawHello;
          printf("  observed likely NMT_Hello; experimental next step is "
                 "NMT_Challenge bunch\n");
          if (experimental_control_replies && it->second.real_ue) {
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
