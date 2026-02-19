#include <iostream>
#include <fstream>
#include <string>
#include <array>
#include <vector>
#include <set>
#include <algorithm>
#include <filesystem>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <stdexcept>

namespace fs = std::filesystem;

class MD5 {
public:
    MD5() { reset(); }

    void update(const void* data, std::size_t len) {
        if (finalized_)
            throw std::logic_error("MD5::update() called after final()");

        auto bytes = static_cast<const unsigned char*>(data);
        std::size_t index = (count_[0] >> 3) & 0x3F;
        std::size_t space = 64 - index;

        uint64_t bits = static_cast<uint64_t>(len) << 3;
        uint64_t total = (static_cast<uint64_t>(count_[1]) << 32) | count_[0];
        total += bits;
        count_[0] = static_cast<uint32_t>(total);
        count_[1] = static_cast<uint32_t>(total >> 32);

        if (len >= space) {
            std::memcpy(&buffer_[index], bytes, space);
            transform(buffer_.data());
            bytes += space;
            len -= space;
            while (len >= 64) {
                transform(bytes);
                bytes += 64;
                len -= 64;
            }
            index = 0;
        }
        std::memcpy(&buffer_[index], bytes, len);
    }

    std::array<unsigned char, 16> final() {
        if (finalized_) return digest_;

        unsigned char padding[64] = {0x80};
        std::fill(padding + 1, padding + 64, 0);
        unsigned char bits[8];
        for (int i = 0; i < 8; ++i)
            bits[i] = static_cast<unsigned char>((count_[i >> 2] >> ((i % 4) * 8)) & 0xFF);
        std::size_t index = (count_[0] >> 3) & 0x3F;
        std::size_t padLen = (index < 56) ? (56 - index) : (120 - index);
        update(padding, padLen);
        update(bits, 8);

        for (int i = 0; i < 4; ++i) {
            digest_[i*4]     = static_cast<unsigned char>(state_[i] & 0xFF);
            digest_[i*4 + 1] = static_cast<unsigned char>((state_[i] >> 8) & 0xFF);
            digest_[i*4 + 2] = static_cast<unsigned char>((state_[i] >> 16) & 0xFF);
            digest_[i*4 + 3] = static_cast<unsigned char>((state_[i] >> 24) & 0xFF);
        }

        finalized_ = true;
        return digest_;
    }

    static std::string from_file(const fs::path& path) {
        std::ifstream file(path, std::ios::binary);
        if (!file) throw std::runtime_error("Cannot open file: " + path.string());

        MD5 ctx;
        char buf[4096];
        while (file.read(buf, sizeof(buf)) || file.gcount())
            ctx.update(buf, static_cast<std::size_t>(file.gcount()));

        if (!file.eof())
            throw std::runtime_error("Read error on file: " + path.string());

        auto digest = ctx.final();
        char hex[33];
        for (int i = 0; i < 16; ++i)
            std::snprintf(hex + i*2, 3, "%02x", digest[i]);
        return std::string(hex, 32);
    }

private:
    void reset() {
        state_[0] = 0x67452301;
        state_[1] = 0xEFCDAB89;
        state_[2] = 0x98BADCFE;
        state_[3] = 0x10325476;
        count_[0] = count_[1] = 0;
        buffer_.fill(0);
        finalized_ = false;
    }

    void transform(const unsigned char* block) {
        uint32_t a = state_[0], b = state_[1], c = state_[2], d = state_[3];
        std::array<uint32_t, 16> x;
        for (int i = 0; i < 16; ++i) {
            x[i] = static_cast<uint32_t>(block[i*4]) |
                   (static_cast<uint32_t>(block[i*4+1]) << 8) |
                   (static_cast<uint32_t>(block[i*4+2]) << 16) |
                   (static_cast<uint32_t>(block[i*4+3]) << 24);
        }

        auto F = [](uint32_t x, uint32_t y, uint32_t z) { return (x & y) | (~x & z); };
        auto G = [](uint32_t x, uint32_t y, uint32_t z) { return (x & z) | (y & ~z); };
        auto H = [](uint32_t x, uint32_t y, uint32_t z) { return x ^ y ^ z; };
        auto I = [](uint32_t x, uint32_t y, uint32_t z) { return y ^ (x | ~z); };

        static auto step = [](auto func, uint32_t& w, uint32_t x, uint32_t y, uint32_t z,
                              uint32_t data, uint32_t s) {
            w += func(x, y, z) + data;
            w = (w << s) | (w >> (32 - s));
            w += x;
        };

        step(F, a, b, c, d, x[0]  + 0xd76aa478, 7);
        step(F, d, a, b, c, x[1]  + 0xe8c7b756, 12);
        step(F, c, d, a, b, x[2]  + 0x242070db, 17);
        step(F, b, c, d, a, x[3]  + 0xc1bdceee, 22);
        step(F, a, b, c, d, x[4]  + 0xf57c0faf, 7);
        step(F, d, a, b, c, x[5]  + 0x4787c62a, 12);
        step(F, c, d, a, b, x[6]  + 0xa8304613, 17);
        step(F, b, c, d, a, x[7]  + 0xfd469501, 22);
        step(F, a, b, c, d, x[8]  + 0x698098d8, 7);
        step(F, d, a, b, c, x[9]  + 0x8b44f7af, 12);
        step(F, c, d, a, b, x[10] + 0xffff5bb1, 17);
        step(F, b, c, d, a, x[11] + 0x895cd7be, 22);
        step(F, a, b, c, d, x[12] + 0x6b901122, 7);
        step(F, d, a, b, c, x[13] + 0xfd987193, 12);
        step(F, c, d, a, b, x[14] + 0xa679438e, 17);
        step(F, b, c, d, a, x[15] + 0x49b40821, 22);

        step(G, a, b, c, d, x[1]  + 0xf61e2562, 5);
        step(G, d, a, b, c, x[6]  + 0xc040b340, 9);
        step(G, c, d, a, b, x[11] + 0x265e5a51, 14);
        step(G, b, c, d, a, x[0]  + 0xe9b6c7aa, 20);
        step(G, a, b, c, d, x[5]  + 0xd62f105d, 5);
        step(G, d, a, b, c, x[10] + 0x02441453, 9);
        step(G, c, d, a, b, x[15] + 0xd8a1e681, 14);
        step(G, b, c, d, a, x[4]  + 0xe7d3fbc8, 20);
        step(G, a, b, c, d, x[9]  + 0x21e1cde6, 5);
        step(G, d, a, b, c, x[14] + 0xc33707d6, 9);
        step(G, c, d, a, b, x[3]  + 0xf4d50d87, 14);
        step(G, b, c, d, a, x[8]  + 0x455a14ed, 20);
        step(G, a, b, c, d, x[13] + 0xa9e3e905, 5);
        step(G, d, a, b, c, x[2]  + 0xfcefa3f8, 9);
        step(G, c, d, a, b, x[7]  + 0x676f02d9, 14);
        step(G, b, c, d, a, x[12] + 0x8d2a4c8a, 20);

        step(H, a, b, c, d, x[5]  + 0xfffa3942, 4);
        step(H, d, a, b, c, x[8]  + 0x8771f681, 11);
        step(H, c, d, a, b, x[11] + 0x6d9d6122, 16);
        step(H, b, c, d, a, x[14] + 0xfde5380c, 23);
        step(H, a, b, c, d, x[1]  + 0xa4beea44, 4);
        step(H, d, a, b, c, x[4]  + 0x4bdecfa9, 11);
        step(H, c, d, a, b, x[7]  + 0xf6bb4b60, 16);
        step(H, b, c, d, a, x[10] + 0xbebfbc70, 23);
        step(H, a, b, c, d, x[13] + 0x289b7ec6, 4);
        step(H, d, a, b, c, x[0]  + 0xeaa127fa, 11);
        step(H, c, d, a, b, x[3]  + 0xd4ef3085, 16);
        step(H, b, c, d, a, x[6]  + 0x04881d05, 23);
        step(H, a, b, c, d, x[9]  + 0xd9d4d039, 4);
        step(H, d, a, b, c, x[12] + 0xe6db99e5, 11);
        step(H, c, d, a, b, x[15] + 0x1fa27cf8, 16);
        step(H, b, c, d, a, x[2]  + 0xc4ac5665, 23);

        step(I, a, b, c, d, x[0]  + 0xf4292244, 6);
        step(I, d, a, b, c, x[7]  + 0x432aff97, 10);
        step(I, c, d, a, b, x[14] + 0xab9423a7, 15);
        step(I, b, c, d, a, x[5]  + 0xfc93a039, 21);
        step(I, a, b, c, d, x[12] + 0x655b59c3, 6);
        step(I, d, a, b, c, x[3]  + 0x8f0ccc92, 10);
        step(I, c, d, a, b, x[10] + 0xffeff47d, 15);
        step(I, b, c, d, a, x[1]  + 0x85845dd1, 21);
        step(I, a, b, c, d, x[8]  + 0x6fa87e4f, 6);
        step(I, d, a, b, c, x[15] + 0xfe2ce6e0, 10);
        step(I, c, d, a, b, x[6]  + 0xa3014314, 15);
        step(I, b, c, d, a, x[13] + 0x4e0811a1, 21);
        step(I, a, b, c, d, x[4]  + 0xf7537e82, 6);
        step(I, d, a, b, c, x[11] + 0xbd3af235, 10);
        step(I, c, d, a, b, x[2]  + 0x2ad7d2bb, 15);
        step(I, b, c, d, a, x[9]  + 0xeb86d391, 21);

        state_[0] += a;
        state_[1] += b;
        state_[2] += c;
        state_[3] += d;
    }

    std::array<uint32_t, 4> state_;
    std::array<uint32_t, 2> count_;
    std::array<unsigned char, 64> buffer_;
    std::array<unsigned char, 16> digest_;
    bool finalized_ = false;
};

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <directory> [--no-prefix]\n";
        return 1;
    }

    fs::path dir = argv[1];
    if (!fs::is_directory(dir)) {
        std::cerr << "Error: not a directory: " << dir << '\n';
        return 1;
    }

    bool add_prefix = true;
    if (argc >= 3 && std::string(argv[2]) == "--no-prefix")
        add_prefix = false;

    fs::path out_path = dir / "hashes.md5";

    std::vector<std::pair<std::string, fs::path>> file_entries;
    std::set<fs::path> visited_dirs;
    std::error_code ec;

    auto opts = fs::directory_options::follow_directory_symlink |
                fs::directory_options::skip_permission_denied;

    for (auto it = fs::recursive_directory_iterator(dir, opts, ec);
         it != fs::recursive_directory_iterator(); it.increment(ec)) {
        if (ec) {
            std::cerr << "Warning: " << ec.message() << " - skipping\n";
            ec.clear();
            continue;
        }

        const auto& path = it->path();

        if (it->is_directory()) {
            fs::path canon = fs::canonical(path, ec);
            if (ec) {
                std::cerr << "Warning: cannot resolve " << path << " - skipping recursion\n";
                it.disable_recursion_pending();
                ec.clear();
                continue;
            }
            if (!visited_dirs.insert(canon).second) {
                it.disable_recursion_pending();
                continue;
            }
        } else if (it->is_regular_file() && path != out_path) {
            file_entries.emplace_back(path.generic_string(), path);
        }
    }

    std::sort(file_entries.begin(), file_entries.end());

    std::ofstream out(out_path);
    if (!out) {
        std::cerr << "Error: cannot create " << out_path << '\n';
        return 1;
    }

    for (const auto& [_, path] : file_entries) {
        std::string hash;
        try {
            hash = MD5::from_file(path);
        } catch (const std::exception& e) {
            std::cerr << "Error: " << e.what() << '\n';
            continue;
        }

        std::string display;
        if (add_prefix) {
            auto rel = fs::relative(path, dir, ec);
            if (!ec)
                display = (fs::path("..") / rel).string();
            else
                display = fs::absolute(path).string();
        } else {
            display = fs::absolute(path).string();
        }

        out << hash << "  " << display << '\n';
    }

    return 0;
}