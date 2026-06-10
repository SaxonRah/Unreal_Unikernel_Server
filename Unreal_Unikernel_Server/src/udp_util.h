#pragma once

#include <stdint.h>
#include <stdio.h>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
using udp_socket_t = SOCKET;
using udp_ssize_t = int;
using udp_socklen_t = int;
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
using udp_socket_t = int;
using udp_ssize_t = ssize_t;
using udp_socklen_t = socklen_t;
#endif

#include <string>

struct UdpClientKey {
  uint32_t ip_be = 0;
  uint16_t port_be = 0;

  bool operator==(const UdpClientKey &o) const {
    return ip_be == o.ip_be && port_be == o.port_be;
  }
};

struct UdpClientKeyHash {
  size_t operator()(const UdpClientKey &k) const {
    uint64_t x = ((uint64_t)k.ip_be << 16) ^ k.port_be;
    x ^= x >> 33;
    x *= 0xff51afd7ed558ccdULL;
    x ^= x >> 33;
    return (size_t)x;
  }
};

bool udp_platform_init();
void udp_platform_cleanup();
udp_socket_t udp_invalid_socket();
bool udp_socket_is_valid(udp_socket_t s);
udp_socket_t udp_create_socket();
void udp_close(udp_socket_t s);
bool udp_set_recv_timeout_ms(udp_socket_t s, int timeout_ms);
const char *udp_last_error_string();
int udp_last_error_code();
bool udp_recv_error_is_transient();
bool udp_recv_error_is_connection_reset();

udp_socket_t udp_bind_any(uint16_t port);
udp_ssize_t udp_recv(udp_socket_t fd, sockaddr_in &from, uint8_t *buf,
                     size_t cap);
bool udp_send(udp_socket_t fd, const sockaddr_in &to, const uint8_t *data,
              size_t n);
bool udp_send_logged(udp_socket_t fd, const sockaddr_in &to,
                     const uint8_t *data, size_t n, FILE *binlog);

UdpClientKey udp_key_from_addr(const sockaddr_in &a);
std::string udp_addr_to_string(const sockaddr_in &a);
std::string udp_hex(const uint8_t *p, size_t n, size_t max_n);

void udp_write_binlog_record(FILE *f, bool inbound, uint64_t unix_seconds,
                             const sockaddr_in &peer, const uint8_t *data,
                             uint32_t n);
