#include "udp_util.h"
#include "ue57_protocol.h"

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <unordered_map>

static volatile sig_atomic_t g_running = 1;

static void on_signal(int) { g_running = 0; }

static uint64_t now_seconds() { return (uint64_t)time(nullptr); }

struct Session {
  ue574::SessionPhase phase = ue574::SessionPhase::CookieValidated;
  uint64_t created = 0;
  uint64_t last_seen = 0;
};

int main(int argc, char **argv) {
  uint16_t port = 7777;
  const char *binlog_path = nullptr;

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
    } else {
      fprintf(stderr, "usage: %s [--port 7777] [--binlog packets.binlog]\n",
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

  int fd = udp_bind_any(port);
  if (fd < 0) {
    return 1;
  }

  printf("UE5 5.7.4 NanoS endpoint starter listening on UDP/%u\n",
         (unsigned)port);
  printf("mode: temporary harness + UE5.7.4 protocol seams\n");
  printf("warning: not UE-wire-compatible until ue57_protocol.cpp TODOs are "
         "replaced\n");

  std::unordered_map<UdpClientKey, Session, UdpClientKeyHash> sessions;
  uint8_t buf[4096];

  while (g_running) {
    sockaddr_in from{};
    ssize_t n = udp_recv(fd, from, buf, sizeof(buf));
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

    printf("rx %zd bytes from %s: %s\n", n, who.c_str(),
           udp_hex(buf, (size_t)n, 96).c_str());

    ue574::ParsedPacket pp = ue574::parse_datagram(from, buf, (size_t)n);

    switch (pp.kind) {
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

      sessions[ck] = Session{ue574::SessionPhase::CookieValidated, ts, ts};

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

    case ue574::PacketKind::ProbablyUEPacketHandlerDatagram:
      printf("  looks like a possible UE PacketHandler datagram; TODO decode "
             "UE5.7.4 bitstream\n");
      printf("  next: compare against 5.7.4 "
             "StatelessConnectHandlerComponent.cpp\n");
      break;

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
  close(fd);
  return 0;
}
