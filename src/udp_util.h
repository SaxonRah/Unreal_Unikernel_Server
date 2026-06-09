#pragma once

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>

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

int udp_bind_any(uint16_t port);
ssize_t udp_recv(int fd, sockaddr_in &from, uint8_t *buf, size_t cap);
bool udp_send(int fd, const sockaddr_in &to, const uint8_t *data, size_t n);
bool udp_send_logged(int fd, const sockaddr_in &to, const uint8_t *data,
                     size_t n, FILE *binlog);

UdpClientKey udp_key_from_addr(const sockaddr_in &a);
std::string udp_addr_to_string(const sockaddr_in &a);
std::string udp_hex(const uint8_t *p, size_t n, size_t max_n);

void udp_write_binlog_record(FILE *f, bool inbound, uint64_t unix_seconds,
                             const sockaddr_in &peer, const uint8_t *data,
                             uint32_t n);
