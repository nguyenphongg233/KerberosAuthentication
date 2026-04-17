#include "kerberos_client.h"

#include <iostream>
#include <sstream>
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

KerberosClient::KerberosClient(std::string client_id, std::string password, std::string tgs_id)
    : client_id_(std::move(client_id)), password_(std::move(password)), tgs_id_(std::move(tgs_id)) {}

bool KerberosClient::login_and_access_service(
    const AuthenticationServer& as_server,
    const TicketGrantingServer& tgs_server,
    ServiceServer& service,
    const std::string& service_id) {
    std::cout << "[Phase 1][Step 1] Sending AS-REQ...\n";
    const auto nonce = generate_nonce();
    auto as_rep = as_server.process_as_req(client_id_, tgs_id_, nonce);
    if (!as_rep.ok) {
        std::cout << "[Client] " << as_rep.message << "\n";
        return false;
    }

    auto client_key = hash_password(password_);
    auto as_plain = decrypt_text(as_rep.encrypted_part_for_client, client_key);
    auto as_parts = split_pipe(as_plain);
    if (as_parts.size() != 4 || as_parts[1] != nonce) {
        std::cout << "[Client] AS-REP invalid (possible wrong password or tampered reply)\n";
        return false;
    }

    auto c_tgs_session_key = as_parts[0];
    auto encrypted_tgt = as_parts[3];
    std::cout << "[Phase 1][Step 2] Received TGT and C-TGS session key.\n";

    std::cout << "[Phase 2][Step 3] Sending TGS-REQ...\n";
    Authenticator tgs_auth{client_id_, now_unix_seconds()};
    auto enc_tgs_auth = encrypt_text(serialize_authenticator(tgs_auth), c_tgs_session_key);
    auto tgs_rep = tgs_server.process_tgs_req(service_id, encrypted_tgt, enc_tgs_auth);
    if (!tgs_rep.ok) {
        std::cout << "[Client] " << tgs_rep.message << "\n";
        return false;
    }

    auto tgs_plain = decrypt_text(tgs_rep.encrypted_part_for_client, c_tgs_session_key);
    auto tgs_parts = split_pipe(tgs_plain);
    if (tgs_parts.size() != 4 || tgs_parts[1] != service_id) {
        std::cout << "[Client] TGS-REP invalid\n";
        return false;
    }

    auto c_s_session_key = tgs_parts[0];
    auto encrypted_service_ticket = tgs_parts[3];
    std::cout << "[Phase 2][Step 4] Received Service Ticket and C-S session key.\n";

    std::cout << "[Phase 3][Step 5] Sending AP-REQ to service...\n";
    Authenticator service_auth{client_id_, now_unix_seconds()};
    auto enc_service_auth = encrypt_text(serialize_authenticator(service_auth), c_s_session_key);
    auto ap_rep = service.process_ap_req(encrypted_service_ticket, enc_service_auth);
    if (!ap_rep.ok) {
        std::cout << "[Client] " << ap_rep.message << "\n";
        return false;
    }

    auto proof_plain = decrypt_text(ap_rep.encrypted_server_proof, c_s_session_key);
    if (proof_plain != std::to_string(service_auth.timestamp + 1)) {
        std::cout << "[Client] AP-REP proof invalid\n";
        return false;
    }

    std::cout << "[Phase 3][Step 6] Mutual authentication success. Service accessed.\n";
    return true;
}

}  // namespace demo
