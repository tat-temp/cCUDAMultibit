// mask.h — custom-charset mask engine (host). Mixed-radix index <-> password,
// hashcat-style keyspace order (position 0 is the fastest-varying digit).
//
// Mask syntax supported here (minimal, extend in Phase 5):
//   ?l a-z   ?u A-Z   ?d 0-9   ?s printable-specials   ?a all printable
//   ?1..?4   user custom sets defined via add_custom('1', "abc...")
//   literal chars are their own 1-symbol charset
#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <array>
#include <stdexcept>

namespace mb {

struct Mask {
    std::vector<std::string> pos;        // charset per position (index 0 = fastest varying)
    std::array<std::string,10> custom{}; // ?1..?9

    void add_custom(char id, const std::string& set) {
        if (id < '1' || id > '9') throw std::runtime_error("custom id must be 1..9");
        custom[id - '0'] = set;
    }

    static std::string builtin(char c) {
        switch (c) {
            case 'l': return "abcdefghijklmnopqrstuvwxyz";
            case 'u': return "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            case 'd': return "0123456789";
            case 's': return " !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";
            case 'a': return "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
                             " !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";
            default:  return std::string();
        }
    }

    // Parse a mask string like "?u?l?l?l?d?d" or "abc?1?1".
    void parse(const std::string& m) {
        pos.clear();
        for (size_t i = 0; i < m.size(); i++) {
            if (m[i] == '?' && i + 1 < m.size()) {
                char c = m[++i];
                if (c == '?') { pos.push_back("?"); continue; }
                std::string set;
                if (c >= '1' && c <= '9') set = custom[c - '0'];
                else set = builtin(c);
                if (set.empty()) throw std::runtime_error(std::string("unknown/empty charset ?") + c);
                pos.push_back(set);
            } else {
                pos.push_back(std::string(1, m[i])); // literal
            }
        }
        if (pos.empty()) throw std::runtime_error("empty mask");
    }

    int length() const { return (int)pos.size(); }

    // total keyspace = product of charset sizes (throws on overflow of 64-bit)
    uint64_t keyspace() const {
        uint64_t n = 1;
        for (auto& s : pos) {
            uint64_t k = s.size();
            if (k == 0) throw std::runtime_error("zero-size position");
            if (n > (UINT64_MAX / k)) throw std::runtime_error("keyspace exceeds 2^64");
            n *= k;
        }
        return n;
    }

    // index -> password bytes (little-endian digit order). out must hold length() bytes.
    void index_to_password(uint64_t idx, uint8_t* out) const {
        for (size_t i = 0; i < pos.size(); i++) {
            uint64_t k = pos[i].size();
            out[i] = (uint8_t)pos[i][idx % k];
            idx /= k;
        }
    }
};

} // namespace mb
