#include "udp_util.h"
#include "ue57_protocol.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static bool recv_packet(int fd, uint8_t *buf, size_t cap, ssize_t &n_out) {
  sockaddr_in from{};
  socklen_t from_len = sizeof(from);
  ssize_t n =
      recvfrom(fd, buf, cap, 0, reinterpret_cast<sockaddr *>(&from), &from_len);
  if (n < 0) {
    fprintf(stderr, "recvfrom: %s\n", strerror(errno));
    return false;
  }
  n_out = n;
  printf("probe rx %zd bytes: %s\n", n, udp_hex(buf, (size_t)n, 128).c_str());
  return true;
}

int main(int argc, char **argv) {
  const char *host = "127.0.0.1";
  uint16_t port = 7777;

  if (argc >= 2)
    host = argv[1];
  if (argc >= 3)
    port = (uint16_t)atoi(argv[2]);

  int fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (fd < 0) {
    fprintf(stderr, "socket: %s\n", strerror(errno));
    return 1;
  }

  struct timeval tv {};
  tv.tv_sec = 2;
  tv.tv_usec = 0;
  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

  sockaddr_in server{};
  server.sin_family = AF_INET;
  server.sin_port = htons(port);
  if (inet_pton(AF_INET, host, &server.sin_addr) != 1) {
    fprintf(stderr, "bad IPv4 host: %s\n", host);
    return 2;
  }

  uint8_t rx[4096];
  ssize_t n = 0;

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
  close(fd);
  return 0;
}
