#pragma once
#include <array>
#include <stddef.h>
#include <stdint.h>

std::array<uint8_t, 20> sha1_bytes(const uint8_t *data, size_t len);

std::array<uint8_t, 20> hmac_sha1(const uint8_t *key, size_t key_len,
                                  const uint8_t *msg, size_t msg_len);

bool constant_time_eq(const uint8_t *a, const uint8_t *b, size_t n);
