// ue5_nanos_handshake_relay_starter
//
// Purpose:
//   Tiny UDP server skeleton for a UE5-compatible unikernel endpoint.
//
// What this is today:
//   - Linux ELF C++17 UDP server suitable for running under NanoS via ops.
//   - Stateless HMAC-SHA1 cookie challenge.
//   - Per-client session creation only after cookie validation.
//   - Hex logging of unknown packets.
//   - A TEMPORARY test wire protocol so the harness can be tested before the
//     real UE5 PacketHandler / ControlChannel bitstream is implemented.
//
// What this is NOT yet:
//   - Not a real UE5 StatelessConnectHandlerComponent implementation.
//   - Not a real UE control-channel serializer.
//   - Not enough for an unmodified UE5 client yet.
//
// Next implementation seam:
//   Replace parse_temp_packet()/send_temp_*() with code matching your exact
//   UE5 branch's StatelessConnectHandlerComponent.cpp and control-channel
//   bunch serialization path.

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include <array>
#include <string>
#include <unordered_map>
#include <vector>

// ------------------------------------------------------------
// Configuration
// ------------------------------------------------------------

static constexpr uint16_t DEFAULT_PORT = 7777;
static constexpr uint32_t COOKIE_TTL_SECONDS = 20;

// Change this per deployment. In production, inject via config/secret.
static constexpr char COOKIE_SECRET[] =
    "CHANGE_ME_32_PLUS_BYTES_RANDOM_FOR_REAL_DEPLOYMENTS";

// Temporary test protocol magic. Real UE packets do NOT look like this.
// Client sends: "UEHS\1"              => server replies challenge.
// Client sends: "UEHS\2" + cookie     => server validates.
// Client sends: "UECTL\1"             => fake NMT_Hello.
// Client sends: "UECTL\3"             => fake NMT_Login.
// Server sends analogous test responses.
static constexpr char TEMP_HS_MAGIC[] = "UEHS";
static constexpr char TEMP_CTL_MAGIC[] = "UECTL";

// ------------------------------------------------------------
// Small utilities
// ------------------------------------------------------------

static volatile sig_atomic_t g_running = 1;

static void on_signal(int) {
    g_running = 0;
}

static uint64_t unix_seconds() {
    return (uint64_t)time(nullptr);
}

static std::string hex_string(const uint8_t* p, size_t n, size_t max_n = 96) {
    static const char* lut = "0123456789abcdef";
    size_t m = n < max_n ? n : max_n;
    std::string out;
    out.reserve(m * 3 + 16);
    for (size_t i = 0; i < m; ++i) {
        out.push_back(lut[p[i] >> 4]);
        out.push_back(lut[p[i] & 15]);
        if (i + 1 != m) out.push_back(' ');
    }
    if (n > max_n) out += " ...";
    return out;
}

static std::string addr_to_string(const sockaddr_in& a) {
    char ip[INET_ADDRSTRLEN] = {};
    inet_ntop(AF_INET, &a.sin_addr, ip, sizeof(ip));
    char buf[64];
    snprintf(buf, sizeof(buf), "%s:%u", ip, (unsigned)ntohs(a.sin_port));
    return std::string(buf);
}

struct ClientKey {
    uint32_t ip_be = 0;
    uint16_t port_be = 0;

    bool operator==(const ClientKey& o) const {
        return ip_be == o.ip_be && port_be == o.port_be;
    }
};

struct ClientKeyHash {
    size_t operator()(const ClientKey& k) const {
        uint64_t x = ((uint64_t)k.ip_be << 16) ^ k.port_be;
        x ^= x >> 33;
        x *= 0xff51afd7ed558ccdULL;
        x ^= x >> 33;
        return (size_t)x;
    }
};

static ClientKey key_from_addr(const sockaddr_in& a) {
    return ClientKey{a.sin_addr.s_addr, a.sin_port};
}

// ------------------------------------------------------------
// Minimal SHA1 + HMAC-SHA1
//
// Public-domain style compact implementation derived from the SHA1 algorithm.
// This is here to keep the first build close to "libc only".
// Replace with vetted crypto if this ever protects real infrastructure.
// ------------------------------------------------------------

struct Sha1 {
    uint32_t h[5];
    uint64_t len = 0;
    uint8_t buf[64];
    size_t buf_len = 0;

    Sha1() {
        h[0] = 0x67452301u;
        h[1] = 0xEFCDAB89u;
        h[2] = 0x98BADCFEu;
        h[3] = 0x10325476u;
        h[4] = 0xC3D2E1F0u;
    }

    static uint32_t rol(uint32_t x, uint32_t n) {
        return (x << n) | (x >> (32 - n));
    }

    void process_block(const uint8_t block[64]) {
        uint32_t w[80];
        for (int i = 0; i < 16; ++i) {
            w[i] = ((uint32_t)block[i*4+0] << 24) |
                   ((uint32_t)block[i*4+1] << 16) |
                   ((uint32_t)block[i*4+2] << 8) |
                   ((uint32_t)block[i*4+3]);
        }
        for (int i = 16; i < 80; ++i) {
            w[i] = rol(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);
        }

        uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4];

        for (int i = 0; i < 80; ++i) {
            uint32_t f, k;
            if (i < 20) {
                f = (b & c) | ((~b) & d);
                k = 0x5A827999u;
            } else if (i < 40) {
                f = b ^ c ^ d;
                k = 0x6ED9EBA1u;
            } else if (i < 60) {
                f = (b & c) | (b & d) | (c & d);
                k = 0x8F1BBCDCu;
            } else {
                f = b ^ c ^ d;
                k = 0xCA62C1D6u;
            }
            uint32_t temp = rol(a, 5) + f + e + k + w[i];
            e = d;
            d = c;
            c = rol(b, 30);
            b = a;
            a = temp;
        }

        h[0] += a;
        h[1] += b;
        h[2] += c;
        h[3] += d;
        h[4] += e;
    }

    void update(const uint8_t* data, size_t n) {
        len += n * 8;
        while (n > 0) {
            size_t take = 64 - buf_len;
            if (take > n) take = n;
            memcpy(buf + buf_len, data, take);
            buf_len += take;
            data += take;
            n -= take;
            if (buf_len == 64) {
                process_block(buf);
                buf_len = 0;
            }
        }
    }

    std::array<uint8_t, 20> final() {
        uint8_t pad = 0x80;
        update(&pad, 1);

        uint8_t zero = 0;
        while (buf_len != 56) {
            if (buf_len > 56) {
                while (buf_len != 64) update(&zero, 1);
            } else {
                update(&zero, 1);
            }
        }

        uint64_t bit_len = len - 8; // compensate? no: update() counted padding too.
        // Correct length must be original message bit length. Track before padding instead.
        // This function is only called once, so recompute by subtracting padding bytes added:
        // Simpler: this implementation stores len including padding; use stored_original_len below.
        // This block intentionally overwritten by final_with_len().
        (void)bit_len;
        return {};
    }

    std::array<uint8_t, 20> final_with_original_bit_len(uint64_t original_bit_len) {
        uint8_t pad = 0x80;
        update(&pad, 1);

        uint8_t zero = 0;
        while (buf_len != 56) {
            update(&zero, 1);
        }

        uint8_t len_be[8];
        for (int i = 0; i < 8; ++i) {
            len_be[7 - i] = (uint8_t)((original_bit_len >> (i * 8)) & 0xff);
        }
        update(len_be, 8);

        std::array<uint8_t, 20> out{};
        for (int i = 0; i < 5; ++i) {
            out[i*4+0] = (uint8_t)(h[i] >> 24);
            out[i*4+1] = (uint8_t)(h[i] >> 16);
            out[i*4+2] = (uint8_t)(h[i] >> 8);
            out[i*4+3] = (uint8_t)(h[i]);
        }
        return out;
    }
};

static std::array<uint8_t, 20> sha1_bytes(const uint8_t* data, size_t len) {
    Sha1 s;
    s.update(data, len);
    return s.final_with_original_bit_len((uint64_t)len * 8);
}

static std::array<uint8_t, 20> hmac_sha1(
    const uint8_t* key, size_t key_len,
    const uint8_t* msg, size_t msg_len
) {
    uint8_t k0[64] = {};
    if (key_len > 64) {
        auto kh = sha1_bytes(key, key_len);
        memcpy(k0, kh.data(), kh.size());
    } else {
        memcpy(k0, key, key_len);
    }

    uint8_t ipad[64], opad[64];
    for (int i = 0; i < 64; ++i) {
        ipad[i] = k0[i] ^ 0x36;
        opad[i] = k0[i] ^ 0x5c;
    }

    std::vector<uint8_t> inner;
    inner.reserve(64 + msg_len);
    inner.insert(inner.end(), ipad, ipad + 64);
    inner.insert(inner.end(), msg, msg + msg_len);
    auto ih = sha1_bytes(inner.data(), inner.size());

    std::vector<uint8_t> outer;
    outer.reserve(64 + ih.size());
    outer.insert(outer.end(), opad, opad + 64);
    outer.insert(outer.end(), ih.begin(), ih.end());
    return sha1_bytes(outer.data(), outer.size());
}

// ------------------------------------------------------------
// Cookie format
// ------------------------------------------------------------
//
// Temporary format:
//   bytes 0..7   unix timestamp, big-endian
//   bytes 8..27  HMAC-SHA1(secret, client_ip || client_port || timestamp)
//
// UE's actual stateless handshake packet format differs. This gives the
// project the correct stateless-auth shape while the real bitstream is added.

using Cookie = std::array<uint8_t, 28>;

static void put_u64_be(uint8_t* p, uint64_t v) {
    for (int i = 0; i < 8; ++i) {
        p[7 - i] = (uint8_t)((v >> (i * 8)) & 0xff);
    }
}

static uint64_t get_u64_be(const uint8_t* p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) {
        v = (v << 8) | p[i];
    }
    return v;
}

static Cookie make_cookie(const sockaddr_in& client, uint64_t ts) {
    Cookie c{};
    put_u64_be(c.data(), ts);

    uint8_t msg[4 + 2 + 8];
    memcpy(msg + 0, &client.sin_addr.s_addr, 4);
    memcpy(msg + 4, &client.sin_port, 2);
    memcpy(msg + 6, c.data(), 8);

    auto mac = hmac_sha1(
        reinterpret_cast<const uint8_t*>(COOKIE_SECRET),
        strlen(COOKIE_SECRET),
        msg,
        sizeof(msg)
    );
    memcpy(c.data() + 8, mac.data(), mac.size());
    return c;
}

static bool constant_time_eq(const uint8_t* a, const uint8_t* b, size_t n) {
    uint8_t d = 0;
    for (size_t i = 0; i < n; ++i) d |= a[i] ^ b[i];
    return d == 0;
}

static bool validate_cookie(const sockaddr_in& client, const uint8_t* data, size_t n) {
    if (n != 28) return false;

    uint64_t ts = get_u64_be(data);
    uint64_t now = unix_seconds();
    if (ts > now + 2) return false;
    if (now - ts > COOKIE_TTL_SECONDS) return false;

    Cookie expected = make_cookie(client, ts);
    return constant_time_eq(data, expected.data(), expected.size());
}

// ------------------------------------------------------------
// Temporary harness packet handling
// ------------------------------------------------------------

enum class TempPacket {
    Unknown,
    HandshakeInitial,
    HandshakeResponse,
    ControlHello,
    ControlLogin,
};

static TempPacket parse_temp_packet(const uint8_t* data, size_t n) {
    if (n >= 5 && memcmp(data, TEMP_HS_MAGIC, 4) == 0) {
        if (data[4] == 1) return TempPacket::HandshakeInitial;
        if (data[4] == 2) return TempPacket::HandshakeResponse;
    }
    if (n >= 6 && memcmp(data, TEMP_CTL_MAGIC, 5) == 0) {
        if (data[5] == 1) return TempPacket::ControlHello;
        if (data[5] == 3) return TempPacket::ControlLogin;
    }
    return TempPacket::Unknown;
}

static bool send_all_udp(int fd, const sockaddr_in& to, const uint8_t* data, size_t n) {
    ssize_t r = sendto(fd, data, n, 0, reinterpret_cast<const sockaddr*>(&to), sizeof(to));
    if (r < 0) {
        fprintf(stderr, "sendto failed: %s\n", strerror(errno));
        return false;
    }
    return (size_t)r == n;
}

static void send_temp_challenge(int fd, const sockaddr_in& to) {
    Cookie c = make_cookie(to, unix_seconds());

    std::vector<uint8_t> out;
    out.insert(out.end(), TEMP_HS_MAGIC, TEMP_HS_MAGIC + 4);
    out.push_back(0x81); // temp server challenge
    out.insert(out.end(), c.begin(), c.end());

    send_all_udp(fd, to, out.data(), out.size());
}

static void send_temp_handshake_ok(int fd, const sockaddr_in& to) {
    const uint8_t out[] = {'U','E','H','S',0x82};
    send_all_udp(fd, to, out, sizeof(out));
}

static void send_temp_control_challenge(int fd, const sockaddr_in& to) {
    const uint8_t out[] = {'U','E','C','T','L',0x82}; // fake NMT_Challenge
    send_all_udp(fd, to, out, sizeof(out));
}

static void send_temp_welcome(int fd, const sockaddr_in& to) {
    const char payload[] =
        "UECTL\x84"
        "Map=/Game/Maps/Minimal\n"
        "Game=/Script/Engine.GameModeBase\n";
    send_all_udp(fd, to, reinterpret_cast<const uint8_t*>(payload), sizeof(payload) - 1);
}

// ------------------------------------------------------------
// Session state
// ------------------------------------------------------------

enum class SessionPhase {
    CookieValidated,
    SawHello,
    Welcomed,
};

struct Session {
    SessionPhase phase = SessionPhase::CookieValidated;
    uint64_t created = 0;
    uint64_t last_seen = 0;
};

static const char* phase_name(SessionPhase p) {
    switch (p) {
        case SessionPhase::CookieValidated: return "CookieValidated";
        case SessionPhase::SawHello: return "SawHello";
        case SessionPhase::Welcomed: return "Welcomed";
    }
    return "?";
}

// ------------------------------------------------------------
// Main
// ------------------------------------------------------------

int main(int argc, char** argv) {
    uint16_t port = DEFAULT_PORT;
    if (argc >= 2) {
        long p = strtol(argv[1], nullptr, 10);
        if (p <= 0 || p > 65535) {
            fprintf(stderr, "bad port: %s\n", argv[1]);
            return 2;
        }
        port = (uint16_t)p;
    }

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        fprintf(stderr, "socket failed: %s\n", strerror(errno));
        return 1;
    }

    int yes = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    sockaddr_in bind_addr{};
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    bind_addr.sin_port = htons(port);

    if (bind(fd, reinterpret_cast<sockaddr*>(&bind_addr), sizeof(bind_addr)) < 0) {
        fprintf(stderr, "bind UDP/%u failed: %s\n", (unsigned)port, strerror(errno));
        close(fd);
        return 1;
    }

    printf("ue5-nanos-handshake-relay-starter listening on UDP/%u\n", (unsigned)port);
    printf("temporary harness protocol enabled; not yet real UE5 wire format\n");

    std::unordered_map<ClientKey, Session, ClientKeyHash> sessions;

    while (g_running) {
        uint8_t buf[2048];
        sockaddr_in from{};
        socklen_t from_len = sizeof(from);

        ssize_t n = recvfrom(fd, buf, sizeof(buf), 0,
                             reinterpret_cast<sockaddr*>(&from), &from_len);
        if (n < 0) {
            if (errno == EINTR) continue;
            fprintf(stderr, "recvfrom failed: %s\n", strerror(errno));
            break;
        }

        std::string who = addr_to_string(from);
        ClientKey ck = key_from_addr(from);
        auto now = unix_seconds();

        printf("rx %zd bytes from %s: %s\n", n, who.c_str(),
               hex_string(buf, (size_t)n).c_str());

        TempPacket tp = parse_temp_packet(buf, (size_t)n);

        if (tp == TempPacket::HandshakeInitial) {
            printf("  temp: handshake initial -> challenge\n");
            send_temp_challenge(fd, from);
            continue;
        }

        if (tp == TempPacket::HandshakeResponse) {
            if ((size_t)n < 5 + 28) {
                printf("  temp: bad handshake response size\n");
                continue;
            }

            bool ok = validate_cookie(from, buf + 5, 28);
            printf("  temp: cookie validation: %s\n", ok ? "ok" : "FAIL");
            if (!ok) continue;

            Session s;
            s.phase = SessionPhase::CookieValidated;
            s.created = now;
            s.last_seen = now;
            sessions[ck] = s;

            send_temp_handshake_ok(fd, from);
            continue;
        }

        auto it = sessions.find(ck);
        if (it == sessions.end()) {
            printf("  no validated session; ignoring non-handshake packet\n");
            continue;
        }

        it->second.last_seen = now;

        if (tp == TempPacket::ControlHello) {
            printf("  temp: fake NMT_Hello -> fake NMT_Challenge\n");
            it->second.phase = SessionPhase::SawHello;
            send_temp_control_challenge(fd, from);
            continue;
        }

        if (tp == TempPacket::ControlLogin) {
            printf("  temp: fake NMT_Login -> fake NMT_Welcome\n");
            it->second.phase = SessionPhase::Welcomed;
            send_temp_welcome(fd, from);
            continue;
        }

        printf("  validated session phase=%s; packet unknown to temp harness\n",
               phase_name(it->second.phase));
    }

    close(fd);
    printf("exiting\n");
    return 0;
}
