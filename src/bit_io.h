#pragma once
#include <stddef.h>
#include <stdint.h>
#include <string>
#include <vector>

namespace ue574 {

class BitWriter {
public:
  void write_bit(bool bit);
  void write_bits_u64(uint64_t value, uint32_t bit_count);
  void write_u8(uint8_t v);
  void write_u16(uint16_t v);
  void write_u32(uint32_t v);
  void write_int_wrapped(uint32_t value, uint32_t max_value);
  void write_int_packed(uint32_t value);
  void append_bits(const BitWriter &other);
  void write_double(double v);
  void write_bytes(const uint8_t *data, size_t n);
  void write_random_bytes(size_t n);
  void write_termination_bit();

  const std::vector<uint8_t> &bytes() const { return data_; }
  uint32_t bit_count() const { return bit_count_; }

private:
  std::vector<uint8_t> data_;
  uint32_t bit_count_ = 0;
};

class BitReader {
public:
  BitReader(const uint8_t *data, size_t bytes);

  bool read_bit(bool &out);
  bool read_bits_u64(uint32_t bit_count, uint64_t &out);
  bool read_u8(uint8_t &out);
  bool read_u16(uint16_t &out);
  bool read_u32(uint32_t &out);
  bool read_int_wrapped(uint32_t max_value, uint32_t &out);
  bool read_int_packed(uint32_t &out);
  bool read_double(double &out);
  bool read_bytes(uint8_t *out, size_t n);

  uint32_t bits_left() const;
  uint32_t pos_bits() const { return pos_bits_; }
  bool error() const { return error_; }
  void set_at_end();

private:
  const uint8_t *data_ = nullptr;
  uint32_t total_bits_ = 0;
  uint32_t pos_bits_ = 0;
  bool error_ = false;
};

std::string bit_dump_lsb(const uint8_t *data, size_t n, size_t max_bits = 160);

} // namespace ue574
