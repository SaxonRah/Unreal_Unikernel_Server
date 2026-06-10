#include "udp_util.h"

#include <errno.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
static char g_udp_errbuf[128];
#else
static char g_udp_errbuf[128];
#endif

bool udp_platform_init() {
#ifdef _WIN32
  static bool initialized = false;
  if (initialized)
    return true;
  WSADATA wsa{};
  int r = WSAStartup(MAKEWORD(2, 2), &wsa);
  if (r != 0) {
    snprintf(g_udp_errbuf, sizeof(g_udp_errbuf), "WSAStartup failed: %d", r);
    return false;
  }
  initialized = true;
#endif
  return true;
}

void udp_platform_cleanup() {
#ifdef _WIN32
  WSACleanup();
#endif
}

udp_socket_t udp_invalid_socket() {
#ifdef _WIN32
  return INVALID_SOCKET;
#else
  return -1;
#endif
}

bool udp_socket_is_valid(udp_socket_t s) {
#ifdef _WIN32
  return s != INVALID_SOCKET;
#else
  return s >= 0;
#endif
}

int udp_last_error_code() {
#ifdef _WIN32
  return WSAGetLastError();
#else
  return errno;
#endif
}

const char *udp_last_error_string() {
#ifdef _WIN32
  int e = WSAGetLastError();
  snprintf(g_udp_errbuf, sizeof(g_udp_errbuf), "WSA error %d", e);
  return g_udp_errbuf;
#else
  return strerror(errno);
#endif
}

bool udp_recv_error_is_transient() {
#ifdef _WIN32
  int e = WSAGetLastError();
  return e == WSAEINTR || e == WSAEWOULDBLOCK || e == WSAETIMEDOUT;
#else
  return errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK;
#endif
}

bool udp_recv_error_is_connection_reset() {
#ifdef _WIN32
  return WSAGetLastError() == WSAECONNRESET;
#else
  return errno == ECONNRESET;
#endif
}

udp_socket_t udp_create_socket() {
  if (!udp_platform_init())
    return udp_invalid_socket();
  udp_socket_t fd = socket(AF_INET, SOCK_DGRAM, 0);
  return fd;
}

void udp_close(udp_socket_t s) {
  if (!udp_socket_is_valid(s))
    return;
#ifdef _WIN32
  closesocket(s);
#else
  close(s);
#endif
}

bool udp_set_recv_timeout_ms(udp_socket_t s, int timeout_ms) {
#ifdef _WIN32
  DWORD tv = (DWORD)timeout_ms;
  return setsockopt(s, SOL_SOCKET, SO_RCVTIMEO,
                    reinterpret_cast<const char *>(&tv), sizeof(tv)) == 0;
#else
  struct timeval tv {};
  tv.tv_sec = timeout_ms / 1000;
  tv.tv_usec = (timeout_ms % 1000) * 1000;
  return setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) == 0;
#endif
}

udp_socket_t udp_bind_any(uint16_t port) {
  udp_socket_t fd = udp_create_socket();
  if (!udp_socket_is_valid(fd)) {
    fprintf(stderr, "socket failed: %s\n", udp_last_error_string());
    return udp_invalid_socket();
  }

  int yes = 1;
  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char *>(&yes),
             sizeof(yes));

  sockaddr_in bind_addr{};
  bind_addr.sin_family = AF_INET;
  bind_addr.sin_addr.s_addr = htonl(INADDR_ANY);
  bind_addr.sin_port = htons(port);

  if (bind(fd, reinterpret_cast<sockaddr *>(&bind_addr), sizeof(bind_addr)) <
      0) {
    fprintf(stderr, "bind UDP/%u failed: %s\n", (unsigned)port,
            udp_last_error_string());
    udp_close(fd);
    return udp_invalid_socket();
  }

#ifdef _WIN32
// Windows reports ICMP Port Unreachable for UDP sockets as WSAECONNRESET on
// recvfrom(). That can happen when the UE client process/socket exits, and
// it is not a protocol failure. Disable that behavior so the endpoint stays
// alive between iterative test runs.
#ifndef SIO_UDP_CONNRESET
#define SIO_UDP_CONNRESET _WSAIOW(IOC_VENDOR, 12)
#endif
  BOOL new_behavior = FALSE;
  DWORD bytes_returned = 0;
  WSAIoctl(fd, SIO_UDP_CONNRESET, &new_behavior, sizeof(new_behavior), nullptr,
           0, &bytes_returned, nullptr, nullptr);
#endif

  return fd;
}

udp_ssize_t udp_recv(udp_socket_t fd, sockaddr_in &from, uint8_t *buf,
                     size_t cap) {
  udp_socklen_t from_len = sizeof(from);
  return recvfrom(fd, reinterpret_cast<char *>(buf), (int)cap, 0,
                  reinterpret_cast<sockaddr *>(&from), &from_len);
}

bool udp_send(udp_socket_t fd, const sockaddr_in &to, const uint8_t *data,
              size_t n) {
  udp_ssize_t r = sendto(fd, reinterpret_cast<const char *>(data), (int)n, 0,
                         reinterpret_cast<const sockaddr *>(&to), sizeof(to));
  if (r < 0) {
    fprintf(stderr, "sendto failed: %s\n", udp_last_error_string());
    return false;
  }
  return (size_t)r == n;
}

bool udp_send_logged(udp_socket_t fd, const sockaddr_in &to,
                     const uint8_t *data, size_t n, FILE *binlog) {
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
  inet_ntop(AF_INET, const_cast<in_addr *>(&a.sin_addr), ip, sizeof(ip));
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
