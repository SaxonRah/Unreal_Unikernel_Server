#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <string>
#include <vector>

#if defined(_WIN32)
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#endif

static uint16_t rd16le(const uint8_t *p) {
  return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}
static uint32_t rd32le(const uint8_t *p) {
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
         ((uint32_t)p[3] << 24);
}
static uint64_t rd64le(const uint8_t *p) {
  uint64_t v = 0;
  for (int i = 7; i >= 0; --i)
    v = (v << 8) | p[i];
  return v;
}

static void print_hex_ascii(const std::vector<uint8_t> &data) {
  const size_t n = data.size();
  for (size_t off = 0; off < n; off += 16) {
    std::printf("  %04zx  ", off);
    for (size_t i = 0; i < 16; ++i) {
      if (off + i < n)
        std::printf("%02x ", data[off + i]);
      else
        std::printf("   ");
      if (i == 7)
        std::printf(" ");
    }
    std::printf(" |");
    for (size_t i = 0; i < 16 && off + i < n; ++i) {
      uint8_t c = data[off + i];
      std::printf("%c", (c >= 32 && c <= 126) ? (char)c : '.');
    }
    std::printf("|\n");
  }
}

static std::string time_string(uint64_t unix_seconds) {
  std::time_t t = (std::time_t)unix_seconds;
  char buf[64] = {};
#if defined(_WIN32)
  std::tm tmv;
  localtime_s(&tmv, &t);
  std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tmv);
#else
  std::tm tmv;
  localtime_r(&t, &tmv);
  std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tmv);
#endif
  return std::string(buf);
}

int main(int argc, char **argv) {
  if (argc < 2) {
    std::fprintf(stderr,
                 "usage: %s <ue574 packet capture .binlog> [--summary]\n",
                 argv[0]);
    std::fprintf(stderr, "note: this is NOT an MSBuild .binlog; it is a U5BL "
                         "raw UDP packet log.\n");
    return 2;
  }
  bool summary = false;
  for (int i = 2; i < argc; ++i) {
    if (std::strcmp(argv[i], "--summary") == 0)
      summary = true;
  }

#if defined(_WIN32)
  WSADATA wsa{};
  WSAStartup(MAKEWORD(2, 2), &wsa);
#endif

  FILE *f = std::fopen(argv[1], "rb");
  if (!f) {
    std::perror(argv[1]);
    return 1;
  }

  uint64_t recno = 0;
  while (true) {
    // U5BL v1 record:
    // magic[4], uint16_le version, uint8 dir, uint8 reserved,
    // uint64_le unix_seconds, IPv4 address in network order,
    // UDP port in network order, uint32_le payload_length, payload bytes.
    uint8_t hdr[26];
    size_t got = std::fread(hdr, 1, sizeof(hdr), f);
    if (got == 0)
      break;
    if (got != sizeof(hdr)) {
      std::fprintf(stderr, "truncated header at record %llu\n",
                   (unsigned long long)(recno + 1));
      return 1;
    }
    if (std::memcmp(hdr, "U5BL", 4) != 0) {
      std::fprintf(stderr,
                   "bad magic at record %llu; this is not a U5BL packet log\n",
                   (unsigned long long)(recno + 1));
      return 1;
    }
    uint16_t ver = rd16le(hdr + 4);
    uint8_t dir = hdr[6];
    uint64_t ts = rd64le(hdr + 8);
    uint32_t ip_be = 0;
    std::memcpy(&ip_be, hdr + 16, sizeof(ip_be));
    uint16_t port_be = 0;
    std::memcpy(&port_be, hdr + 20, sizeof(port_be));
    uint32_t len = rd32le(hdr + 22);

    if (ver != 1) {
      std::fprintf(stderr, "unsupported U5BL version %u at record %llu\n",
                   (unsigned)ver, (unsigned long long)(recno + 1));
      return 1;
    }
    if (len > 16 * 1024 * 1024) {
      std::fprintf(stderr, "unreasonable payload length %u at record %llu\n",
                   len, (unsigned long long)(recno + 1));
      return 1;
    }
    std::vector<uint8_t> data(len);
    if (len && std::fread(data.data(), 1, len, f) != len) {
      std::fprintf(stderr, "truncated payload at record %llu\n",
                   (unsigned long long)(recno + 1));
      return 1;
    }

    char ipbuf[64] = {};
    in_addr ia{};
    ia.s_addr = ip_be;
    const char *ipstr = inet_ntop(AF_INET, &ia, ipbuf, sizeof(ipbuf));
    if (!ipstr)
      ipstr = "?.?.?.?";
    uint16_t port = ntohs(port_be);
    const char *d = (dir == 1) ? "rx" : (dir == 2) ? "tx" : "??";

    std::printf("#%llu %s %s %s:%u len=%u\n", (unsigned long long)(recno + 1),
                d, time_string(ts).c_str(), ipstr, port, len);
    if (!summary)
      print_hex_ascii(data);
    ++recno;
  }
  std::printf("records=%llu\n", (unsigned long long)recno);
  std::fclose(f);
#if defined(_WIN32)
  WSACleanup();
#endif
  return 0;
}
