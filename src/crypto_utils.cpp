#include "crypto_utils.h"

#include <chrono>
#include <iomanip>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>

namespace demo {
namespace {

std::string to_hex(const std::string& bytes) {
    std::ostringstream oss;
    for (unsigned char c : bytes) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(c);
    }
    return oss.str();
}

std::string from_hex(const std::string& hex) {
    if (hex.size() % 2 != 0) {
        throw std::runtime_error("Invalid hex size");
    }

    std::string out;
    out.reserve(hex.size() / 2);

    for (size_t i = 0; i < hex.size(); i += 2) {
        auto byte = static_cast<char>(std::stoi(hex.substr(i, 2), nullptr, 16));
        out.push_back(byte);
    }

    return out;
}

std::string xor_stream(const std::string& input, const std::string& key) {
    if (key.empty()) {
        throw std::runtime_error("Encryption key cannot be empty");
    }

    std::string output = input;
    for (size_t i = 0; i < input.size(); ++i) {
        output[i] = static_cast<char>(input[i] ^ key[i % key.size()]);
    }
    return output;
}

std::string random_token(size_t len) {
    static const char alphabet[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    static thread_local std::mt19937 rng(std::random_device{}());
    std::uniform_int_distribution<size_t> dist(0, sizeof(alphabet) - 2);

    std::string token;
    token.reserve(len);
    for (size_t i = 0; i < len; ++i) {
        token.push_back(alphabet[dist(rng)]);
    }
    return token;
}

}  // namespace

std::string hash_password(const std::string& password) {
    auto hashed = std::hash<std::string>{}(password);
    std::stringstream ss;
    ss << std::hex << hashed;
    return ss.str();
}

std::string generate_nonce() {
    return random_token(16);
}

std::string generate_session_key() {
    return random_token(24);
}

long now_unix_seconds() {
    return static_cast<long>(std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch())
                                 .count());
}

std::string encrypt_text(const std::string& plaintext, const std::string& key) {
    return to_hex(xor_stream(plaintext, key));
}

std::string decrypt_text(const std::string& ciphertext_hex, const std::string& key) {
    return xor_stream(from_hex(ciphertext_hex), key);
}

}  // namespace demo
