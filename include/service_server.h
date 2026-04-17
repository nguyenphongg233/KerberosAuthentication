#pragma once

#include <string>
#include <unordered_map>

namespace demo {

struct ApResponse {
    bool ok;
    std::string message;
    std::string encrypted_server_proof;
};

class ServiceServer {
public:
    explicit ServiceServer(std::string service_secret);

    ApResponse process_ap_req(
        const std::string& encrypted_service_ticket,
        const std::string& encrypted_authenticator);

private:
    std::string service_secret_;
    std::unordered_map<std::string, long> latest_timestamp_by_client_;
};

}  // namespace demo
