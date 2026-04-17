#include "tgs_server.h"

#include <sstream>
#include <stdexcept>
#include <vector>

#include "crypto_utils.h"
#include "messages.h"

namespace demo {
namespace {

std::vector<std::string> split_pipe(const std::string& input) {
    std::vector<std::string> parts;
    std::stringstream ss(input);
    std::string item;
    while (std::getline(ss, item, '|')) {
        parts.push_back(item);
    }
    return parts;
}

}  // namespace

TicketGrantingServer::TicketGrantingServer(
    std::string tgs_secret,
    std::unordered_map<std::string, std::string> service_secrets,
    long ticket_lifetime_sec)
    : tgs_secret_(std::move(tgs_secret)),
      service_secrets_(std::move(service_secrets)),
      ticket_lifetime_sec_(ticket_lifetime_sec) {}

TgsResponse TicketGrantingServer::process_tgs_req(
    const std::string& service_id,
    const std::string& encrypted_tgt,
    const std::string& encrypted_authenticator) const {
    auto svc_it = service_secrets_.find(service_id);
    if (svc_it == service_secrets_.end()) {
        return TgsResponse{false, "TGS-REQ rejected: unknown service", ""};
    }

    try {
        auto tgt = deserialize_ticket(decrypt_text(encrypted_tgt, tgs_secret_));
        if (now_unix_seconds() > tgt.expires_at) {
            return TgsResponse{false, "TGS-REQ rejected: TGT expired", ""};
        }

        auto auth = deserialize_authenticator(decrypt_text(encrypted_authenticator, tgt.session_key));
        if (auth.client_id != tgt.client_id) {
            return TgsResponse{false, "TGS-REQ rejected: client mismatch", ""};
        }

        auto skew = now_unix_seconds() - auth.timestamp;
        if (skew < -60 || skew > 60) {
            return TgsResponse{false, "TGS-REQ rejected: authenticator out of allowed skew", ""};
        }

        auto c_s_session_key = generate_session_key();
        auto expiry = now_unix_seconds() + ticket_lifetime_sec_;

        Ticket service_ticket{tgt.client_id, service_id, c_s_session_key, expiry};
        auto encrypted_service_ticket = encrypt_text(serialize_ticket(service_ticket), svc_it->second);

        auto plain_for_client = c_s_session_key + "|" + service_id + "|" + std::to_string(expiry) + "|" + encrypted_service_ticket;
        auto encrypted_for_client = encrypt_text(plain_for_client, tgt.session_key);

        return TgsResponse{true, "TGS-REP issued", encrypted_for_client};
    } catch (const std::exception&) {
        return TgsResponse{false, "TGS-REQ rejected: malformed ticket/authenticator", ""};
    }
}

}  // namespace demo
