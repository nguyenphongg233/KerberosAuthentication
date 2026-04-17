#pragma once

#include <string>

#include "kdc_database.h"

namespace demo {

struct AsResponse {
    bool ok;
    std::string message;
    std::string encrypted_part_for_client;
};

class AuthenticationServer {
public:
    AuthenticationServer(const KdcDatabase& db, std::string tgs_secret, long ticket_lifetime_sec = 300);

    AsResponse process_as_req(
        const std::string& client_id,
        const std::string& tgs_id,
        const std::string& nonce) const;

private:
    const KdcDatabase& db_;
    std::string tgs_secret_;
    long ticket_lifetime_sec_;
};

}  // namespace demo
