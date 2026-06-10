#include "udp_util.h"
#include "ue57_protocol.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static bool recv_packet(udp_socket_t fd, uint8_t *buf, size_t cap,
                        udp_ssize_t &n_out) {
  sockaddr_in from{};
  udp_ssize_t n = udp_recv(fd, from, buf, cap);
  if (n < 0) {
    fprintf(stderr, "recvfrom: %s\n", udp_last_error_string());
    return false;
  }
  n_out = n;
  printf("probe rx %lld bytes: %s\n", (long long)n,
         udp_hex(buf, (size_t)n, 128).c_str());
  return true;
}

int main(int argc, char **argv) {
  const char *host = "127.0.0.1";
  uint16_t port = 7777;

  if (argc >= 2)
    host = argv[1];
  if (argc >= 3)
    port = (uint16_t)atoi(argv[2]);

  udp_socket_t fd = udp_create_socket();
  if (!udp_socket_is_valid(fd)) {
    fprintf(stderr, "socket: %s\n", udp_last_error_string());
    return 1;
  }
  udp_set_recv_timeout_ms(fd, 2000);

  sockaddr_in server{};
  server.sin_family = AF_INET;
  server.sin_port = htons(port);
  if (inet_pton(AF_INET, host, &server.sin_addr) != 1) {
    fprintf(stderr, "bad IPv4 host: %s\n", host);
    return 2;
  }

  uint8_t rx[4096];
  udp_ssize_t n = 0;

  auto initial = ue574::build_ue574_initial(
      1,
      0x12345678u, // dummy NetworkVersion for probe only
      0x0000);

  printf("probe tx UE5.7.4-shaped Initial, %zu bytes\n", initial.size());
  udp_send(fd, server, initial.data(), initial.size());

  if (!recv_packet(fd, rx, sizeof(rx), n))
    return 1;

  ue574::UEHandshake challenge =
      ue574::try_parse_ue574_handshake(rx, (size_t)n);
  if (!challenge.recognized ||
      challenge.packet_type != ue574::HandshakeTypeChallenge) {
    fprintf(stderr, "did not receive parseable Challenge\n");
    return 1;
  }

  printf("probe parsed Challenge: session=%u client=%u min=%u cur=%u sent=%u "
         "ts=%.3f\n",
         (unsigned)challenge.session_id, (unsigned)challenge.client_id,
         (unsigned)challenge.remote_min_version,
         (unsigned)challenge.remote_cur_version,
         (unsigned)challenge.remote_sent_count, challenge.timestamp);

  auto response = ue574::build_ue574_response(challenge);
  printf("probe tx UE5.7.4-shaped Response, %zu bytes\n", response.size());
  udp_send(fd, server, response.data(), response.size());

  if (!recv_packet(fd, rx, sizeof(rx), n))
    return 1;

  ue574::UEHandshake ack = ue574::try_parse_ue574_handshake(rx, (size_t)n);
  if (!ack.recognized || ack.packet_type != ue574::HandshakeTypeAck ||
      ack.timestamp >= 0.0) {
    fprintf(stderr, "did not receive parseable Ack\n");
    return 1;
  }

  printf(
      "probe parsed Ack: session=%u client=%u min=%u cur=%u sent=%u ts=%.3f\n",
      (unsigned)ack.session_id, (unsigned)ack.client_id,
      (unsigned)ack.remote_min_version, (unsigned)ack.remote_cur_version,
      (unsigned)ack.remote_sent_count, ack.timestamp);

  printf("UE5.7.4-shaped stateless handshake probe complete\n");
  udp_close(fd);
  return 0;
}
