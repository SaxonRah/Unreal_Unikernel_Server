#include "bit_io.h"

#include <stdlib.h>
#include <string.h>

namespace ue574 {

void BitWriter::write_bit(bool bit) {
    uint32_t byte_index = bit_count_ >> 3;
    uint32_t bit_index = bit_count_ & 7;

    if (byte_index >= data_.size()) {
        data_.push_back(0);
    }

    if (bit) {
        data_[byte_index] |= (uint8_t)(1u << bit_index);
    }

    bit_count_++;
}

void BitWriter::write_bits_u64(uint64_t value, uint32_t bit_count) {
    for (uint32_t i = 0; i < bit_count; ++i) {
        write_bit(((value >> i) & 1u) != 0);
    }
}

void BitWriter::write_u8(uint8_t v) {
    write_bits_u64(v, 8);
}

void BitWriter::write_u16(uint16_t v) {
    write_bits_u64(v, 16);
}

void BitWriter::write_u32(uint32_t v) {
    write_bits_u64(v, 32);
}

static uint32_t ceil_log2_local(uint32_t max_value) {
    uint32_t v = max_value > 0 ? max_value - 1 : 0;
    uint32_t bits = 0;
    while (v > 0) { ++bits; v >>= 1; }
    return bits;
}

void BitWriter::write_int_wrapped(uint32_t value, uint32_t max_value) {
    write_bits_u64(value, ceil_log2_local(max_value));
}

void BitWriter::write_int_packed(uint32_t value) {
    // Matches the small-value shape used by UE SerializeIntPacked: 7 data
    // bits then a continuation bit. Channel 0 encodes as one zero byte.
    do {
        uint8_t low7 = (uint8_t)(value & 0x7fu);
        value >>= 7;
        write_bits_u64(low7, 7);
        write_bit(value != 0);
    } while (value != 0);
}

void BitWriter::append_bits(const BitWriter& other) {
    BitReader r(other.bytes().data(), other.bytes().size());
    for (uint32_t i = 0; i < other.bit_count(); ++i) {
        bool b = false;
        r.read_bit(b);
        write_bit(b);
    }
}

void BitWriter::write_double(double v) {
    uint64_t raw = 0;
    static_assert(sizeof(raw) == sizeof(v), "unexpected double size");
    memcpy(&raw, &v, sizeof(raw));
    write_bits_u64(raw, 64);
}

void BitWriter::write_bytes(const uint8_t* data, size_t n) {
    for (size_t i = 0; i < n; ++i) {
        write_u8(data[i]);
    }
}

void BitWriter::write_random_bytes(size_t n) {
    for (size_t i = 0; i < n; ++i) {
        // Same broad shape as UE's non-crypto random filler. Not security-sensitive.
        write_u8((uint8_t)(rand() % 255));
    }
}

void BitWriter::write_termination_bit() {
    write_bit(true);
}

BitReader::BitReader(const uint8_t* data, size_t bytes)
    : data_(data), total_bits_((uint32_t)(bytes * 8)), pos_bits_(0) {}

bool BitReader::read_bit(bool& out) {
    if (pos_bits_ >= total_bits_) {
        error_ = true;
        out = false;
        return false;
    }

    uint32_t byte_index = pos_bits_ >> 3;
    uint32_t bit_index = pos_bits_ & 7;
    out = ((data_[byte_index] >> bit_index) & 1u) != 0;
    pos_bits_++;
    return true;
}

bool BitReader::read_bits_u64(uint32_t bit_count, uint64_t& out) {
    out = 0;

    if (bit_count > 64) {
        error_ = true;
        return false;
    }

    for (uint32_t i = 0; i < bit_count; ++i) {
        bool b = false;
        if (!read_bit(b)) return false;
        if (b) out |= (uint64_t(1) << i);
    }

    return true;
}

bool BitReader::read_u8(uint8_t& out) {
    uint64_t v = 0;
    if (!read_bits_u64(8, v)) {
        out = 0;
        return false;
    }
    out = (uint8_t)v;
    return true;
}

bool BitReader::read_u16(uint16_t& out) {
    uint64_t v = 0;
    if (!read_bits_u64(16, v)) {
        out = 0;
        return false;
    }
    out = (uint16_t)v;
    return true;
}

bool BitReader::read_u32(uint32_t& out) {
    uint64_t v = 0;
    if (!read_bits_u64(32, v)) {
        out = 0;
        return false;
    }
    out = (uint32_t)v;
    return true;
}

bool BitReader::read_int_wrapped(uint32_t max_value, uint32_t& out) {
    uint64_t tmp = 0;
    if (!read_bits_u64(ceil_log2_local(max_value), tmp)) { out = 0; return false; }
    out = (uint32_t)tmp;
    return true;
}

bool BitReader::read_int_packed(uint32_t& out) {
    out = 0;
    uint32_t shift = 0;
    for (int group = 0; group < 5; ++group) {
        uint64_t low7 = 0;
        if (!read_bits_u64(7, low7)) return false;
        bool more = false;
        if (!read_bit(more)) return false;
        out |= (uint32_t)(low7 << shift);
        if (!more) return true;
        shift += 7;
    }
    return false;
}

bool BitReader::read_double(double& out) {
    uint64_t raw = 0;
    if (!read_bits_u64(64, raw)) {
        out = 0.0;
        return false;
    }
    memcpy(&out, &raw, sizeof(out));
    return true;
}

bool BitReader::read_bytes(uint8_t* out, size_t n) {
    for (size_t i = 0; i < n; ++i) {
        if (!read_u8(out[i])) return false;
    }
    return true;
}

uint32_t BitReader::bits_left() const {
    return total_bits_ > pos_bits_ ? total_bits_ - pos_bits_ : 0;
}

void BitReader::set_at_end() {
    pos_bits_ = total_bits_;
}

std::string bit_dump_lsb(const uint8_t* data, size_t n, size_t max_bits) {
    size_t total = n * 8;
    if (total > max_bits) total = max_bits;

    std::string out;
    out.reserve(total + 16);

    for (size_t i = 0; i < total; ++i) {
        bool b = ((data[i >> 3] >> (i & 7)) & 1u) != 0;
        out.push_back(b ? '1' : '0');
        if ((i & 7) == 7) out.push_back(' ');
    }

    if (n * 8 > max_bits) out += "...";
    return out;
}

}
