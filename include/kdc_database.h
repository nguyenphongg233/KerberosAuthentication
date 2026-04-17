#pragma once

#include <string>
#include <unordered_map>

namespace demo {

struct PrincipalRecord {
    std::string principal_id;
    std::string password_hash;
};

class KdcDatabase {
public:
    void add_client(const std::string& client_id, const std::string& password);
    bool has_client(const std::string& client_id) const;
    std::string get_client_long_term_key(const std::string& client_id) const;

    bool validate_client_secret(const std::string& client_id, const std::string& password) const;
    std::string get_client_key(const std::string& client_id, const std::string& password) const;

private:
    std::unordered_map<std::string, PrincipalRecord> clients_;
};

}  // namespace demo
