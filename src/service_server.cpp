#include "service_server.h"

#include <stdexcept>

#include "crypto_utils.h"
#include "messages.h"

namespace demo {

ServiceServer::ServiceServer(std::string service_secret) : service_secret_(std::move(service_secret)) {}

ApResponse ServiceServer::process_ap_req(
    const std::string& encrypted_service_ticket,
    const std::string& encrypted_authenticator) {
    try {
        auto service_ticket = deserialize_ticket(decrypt_text(encrypted_service_ticket, service_secret_));
        if (now_unix_seconds() > service_ticket.expires_at) {
            return ApResponse{false, "AP-REQ rejected: service ticket expired", ""};
        }

        auto auth = deserialize_authenticator(decrypt_text(encrypted_authenticator, service_ticket.session_key));
        if (auth.client_id != service_ticket.client_id) {
            return ApResponse{false, "AP-REQ rejected: client mismatch", ""};
        }

        auto skew = now_unix_seconds() - auth.timestamp;
        if (skew < -60 || skew > 60) {
            return ApResponse{false, "AP-REQ rejected: timestamp out of allowed skew", ""};
        }

        auto latest_it = latest_timestamp_by_client_.find(auth.client_id);
        if (latest_it != latest_timestamp_by_client_.end() && auth.timestamp <= latest_it->second) {
            return ApResponse{false, "AP-REQ rejected: replay detected", ""};
        }
        latest_timestamp_by_client_[auth.client_id] = auth.timestamp;

        auto server_proof = encrypt_text(std::to_string(auth.timestamp + 1), service_ticket.session_key);
        return ApResponse{true, "AP-REP issued", server_proof};
    } catch (const std::exception&) {
        return ApResponse{false, "AP-REQ rejected: malformed service ticket/authenticator", ""};
    }
}

}  // namespace demo
