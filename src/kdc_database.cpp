#include "kdc_database.h"

#include <stdexcept>

#include "crypto_utils.h"

namespace demo {

void KdcDatabase::add_client(const std::string& client_id, const std::string& password) {
    clients_[client_id] = PrincipalRecord{client_id, hash_password(password)};
}

bool KdcDatabase::has_client(const std::string& client_id) const {
    return clients_.find(client_id) != clients_.end();
}

std::string KdcDatabase::get_client_long_term_key(const std::string& client_id) const {
    auto it = clients_.find(client_id);
    if (it == clients_.end()) {
        throw std::runtime_error("Unknown client principal");
    }
    return it->second.password_hash;
}

bool KdcDatabase::validate_client_secret(const std::string& client_id, const std::string& password) const {
    auto it = clients_.find(client_id);
    if (it == clients_.end()) {
        return false;
    }
    return it->second.password_hash == hash_password(password);
}

std::string KdcDatabase::get_client_key(const std::string& client_id, const std::string& password) const {
    if (!validate_client_secret(client_id, password)) {
        throw std::runtime_error("Client credential mismatch");
    }
    return hash_password(password);
}

}  // namespace demo
