#pragma once

#include <string>

namespace demo {

std::string hash_password(const std::string& password);
std::string generate_nonce();
std::string generate_session_key();
long now_unix_seconds();

std::string encrypt_text(const std::string& plaintext, const std::string& key);
std::string decrypt_text(const std::string& ciphertext_hex, const std::string& key);

}  // namespace demo
