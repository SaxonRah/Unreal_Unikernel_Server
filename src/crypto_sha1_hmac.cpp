#include "crypto_sha1_hmac.h"

#include <string.h>
#include <vector>

struct Sha1 {
  uint32_t h[5];
  uint64_t original_len_bits = 0;
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
      w[i] = ((uint32_t)block[i * 4 + 0] << 24) |
             ((uint32_t)block[i * 4 + 1] << 16) |
             ((uint32_t)block[i * 4 + 2] << 8) | ((uint32_t)block[i * 4 + 3]);
    }

    for (int i = 16; i < 80; ++i) {
      w[i] = rol(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
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

  void update_raw(const uint8_t *data, size_t n) {
    while (n > 0) {
      size_t take = 64 - buf_len;
      if (take > n)
        take = n;
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

  void update(const uint8_t *data, size_t n) {
    original_len_bits += (uint64_t)n * 8;
    update_raw(data, n);
  }

  std::array<uint8_t, 20> final() {
    uint8_t one = 0x80;
    update_raw(&one, 1);

    uint8_t zero = 0;
    while (buf_len != 56) {
      update_raw(&zero, 1);
    }

    uint8_t len_be[8];
    for (int i = 0; i < 8; ++i) {
      len_be[7 - i] = (uint8_t)((original_len_bits >> (i * 8)) & 0xff);
    }
    update_raw(len_be, 8);

    std::array<uint8_t, 20> out{};
    for (int i = 0; i < 5; ++i) {
      out[i * 4 + 0] = (uint8_t)(h[i] >> 24);
      out[i * 4 + 1] = (uint8_t)(h[i] >> 16);
      out[i * 4 + 2] = (uint8_t)(h[i] >> 8);
      out[i * 4 + 3] = (uint8_t)(h[i]);
    }
    return out;
  }
};

std::array<uint8_t, 20> sha1_bytes(const uint8_t *data, size_t len) {
  Sha1 s;
  s.update(data, len);
  return s.final();
}

std::array<uint8_t, 20> hmac_sha1(const uint8_t *key, size_t key_len,
                                  const uint8_t *msg, size_t msg_len) {
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

bool constant_time_eq(const uint8_t *a, const uint8_t *b, size_t n) {
  uint8_t d = 0;
  for (size_t i = 0; i < n; ++i)
    d |= a[i] ^ b[i];
  return d == 0;
}
