#include "udp_util.h"

#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

int udp_bind_any(uint16_t port) {
  int fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (fd < 0) {
    fprintf(stderr, "socket failed: %s\n", strerror(errno));
    return -1;
  }

  int yes = 1;
  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

  sockaddr_in bind_addr{};
  bind_addr.sin_family = AF_INET;
  bind_addr.sin_addr.s_addr = htonl(INADDR_ANY);
  bind_addr.sin_port = htons(port);

  if (bind(fd, reinterpret_cast<sockaddr *>(&bind_addr), sizeof(bind_addr)) <
      0) {
    fprintf(stderr, "bind UDP/%u failed: %s\n", (unsigned)port,
            strerror(errno));
    close(fd);
    return -1;
  }

  return fd;
}

ssize_t udp_recv(int fd, sockaddr_in &from, uint8_t *buf, size_t cap) {
  socklen_t from_len = sizeof(from);
  return recvfrom(fd, buf, cap, 0, reinterpret_cast<sockaddr *>(&from),
                  &from_len);
}

bool udp_send(int fd, const sockaddr_in &to, const uint8_t *data, size_t n) {
  ssize_t r = sendto(fd, data, n, 0, reinterpret_cast<const sockaddr *>(&to),
                     sizeof(to));
  if (r < 0) {
    fprintf(stderr, "sendto failed: %s\n", strerror(errno));
    return false;
  }
  return (size_t)r == n;
}

bool udp_send_logged(int fd, const sockaddr_in &to, const uint8_t *data,
                     size_t n, FILE *binlog) {
  bool ok = udp_send(fd, to, data, n);
  if (ok && binlog) {
    udp_write_binlog_record(binlog, false, (uint64_t)time(nullptr), to, data,
                            (uint32_t)n);
  }
  return ok;
}

UdpClientKey udp_key_from_addr(const sockaddr_in &a) {
  return UdpClientKey{a.sin_addr.s_addr, a.sin_port};
}

std::string udp_addr_to_string(const sockaddr_in &a) {
  char ip[INET_ADDRSTRLEN] = {};
  inet_ntop(AF_INET, &a.sin_addr, ip, sizeof(ip));
  char buf[64];
  snprintf(buf, sizeof(buf), "%s:%u", ip, (unsigned)ntohs(a.sin_port));
  return std::string(buf);
}

std::string udp_hex(const uint8_t *p, size_t n, size_t max_n) {
  static const char *lut = "0123456789abcdef";
  size_t m = n < max_n ? n : max_n;
  std::string out;
  out.reserve(m * 3 + 16);
  for (size_t i = 0; i < m; ++i) {
    out.push_back(lut[p[i] >> 4]);
    out.push_back(lut[p[i] & 15]);
    if (i + 1 != m)
      out.push_back(' ');
  }
  if (n > max_n)
    out += " ...";
  return out;
}

void udp_write_binlog_record(FILE *f, bool inbound, uint64_t unix_seconds,
                             const sockaddr_in &peer, const uint8_t *data,
                             uint32_t n) {
  // Simple append-only binary log:
  // magic "U5BL", version u16=1, dir u8, reserved u8,
  // unix seconds u64, ip_be u32, port_be u16, len u32, data[len].
  const uint8_t magic[4] = {'U', '5', 'B', 'L'};
  uint16_t ver = 1;
  uint8_t dir = inbound ? 1 : 2;
  uint8_t reserved = 0;

  fwrite(magic, 1, 4, f);
  fwrite(&ver, 1, sizeof(ver), f);
  fwrite(&dir, 1, sizeof(dir), f);
  fwrite(&reserved, 1, sizeof(reserved), f);
  fwrite(&unix_seconds, 1, sizeof(unix_seconds), f);
  fwrite(&peer.sin_addr.s_addr, 1, sizeof(peer.sin_addr.s_addr), f);
  fwrite(&peer.sin_port, 1, sizeof(peer.sin_port), f);
  fwrite(&n, 1, sizeof(n), f);
  fwrite(data, 1, n, f);
  fflush(f);
}
