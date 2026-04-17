#pragma once

#include <string>
#include <unordered_map>

namespace demo {

struct TgsResponse {
    bool ok;
    std::string message;
    std::string encrypted_part_for_client;
};

class TicketGrantingServer {
public:
    TicketGrantingServer(
        std::string tgs_secret,
        std::unordered_map<std::string, std::string> service_secrets,
        long ticket_lifetime_sec = 300);

    TgsResponse process_tgs_req(
        const std::string& service_id,
        const std::string& encrypted_tgt,
        const std::string& encrypted_authenticator) const;

private:
    std::string tgs_secret_;
    std::unordered_map<std::string, std::string> service_secrets_;
    long ticket_lifetime_sec_;
};

}  // namespace demo
