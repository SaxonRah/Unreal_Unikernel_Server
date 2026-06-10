#include "udp_util.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <vector>

static bool recv_once(udp_socket_t fd, uint8_t *buf, size_t cap,
                      udp_ssize_t &n_out) {
  sockaddr_in from{};
  udp_ssize_t n = udp_recv(fd, from, buf, cap);
  if (n < 0) {
    fprintf(stderr, "recvfrom: %s\n", udp_last_error_string());
    return false;
  }
  n_out = n;
  printf("client rx %lld bytes: %s\n", (long long)n,
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

  uint8_t rx[2048];
  udp_ssize_t n = 0;

  const uint8_t hs1[] = {'U', 'E', 'H', 'S', 1};
  printf("client tx temp handshake initial\n");
  udp_send(fd, server, hs1, sizeof(hs1));
  if (!recv_once(fd, rx, sizeof(rx), n))
    return 1;

  if (n != 5 + 28 || memcmp(rx, "UEHS", 4) != 0 || rx[4] != 0x81) {
    fprintf(stderr, "unexpected challenge packet\n");
    return 1;
  }

  std::vector<uint8_t> hs2 = {'U', 'E', 'H', 'S', 2};
  hs2.insert(hs2.end(), rx + 5, rx + 5 + 28);

  printf("client tx temp handshake response\n");
  udp_send(fd, server, hs2.data(), hs2.size());
  if (!recv_once(fd, rx, sizeof(rx), n))
    return 1;

  const uint8_t hello[] = {'U', 'E', 'C', 'T', 'L', 1};
  printf("client tx fake NMT_Hello\n");
  udp_send(fd, server, hello, sizeof(hello));
  if (!recv_once(fd, rx, sizeof(rx), n))
    return 1;

  const uint8_t login[] = {'U', 'E', 'C', 'T', 'L', 3};
  printf("client tx fake NMT_Login\n");
  udp_send(fd, server, login, sizeof(login));
  if (!recv_once(fd, rx, sizeof(rx), n))
    return 1;

  printf("temporary flow complete\n");
  udp_close(fd);
  return 0;
}
