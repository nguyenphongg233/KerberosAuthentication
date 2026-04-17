#include "as_server.h"

#include <stdexcept>

#include "crypto_utils.h"
#include "messages.h"

namespace demo {

AuthenticationServer::AuthenticationServer(const KdcDatabase& db, std::string tgs_secret, long ticket_lifetime_sec)
    : db_(db), tgs_secret_(std::move(tgs_secret)), ticket_lifetime_sec_(ticket_lifetime_sec) {}

AsResponse AuthenticationServer::process_as_req(
    const std::string& client_id,
    const std::string& tgs_id,
    const std::string& nonce) const {
    if (!db_.has_client(client_id)) {
        return AsResponse{false, "AS-REQ rejected: unknown client principal", ""};
    }

    auto c_tgs_session_key = generate_session_key();
    auto expiry = now_unix_seconds() + ticket_lifetime_sec_;

    Ticket tgt{client_id, tgs_id, c_tgs_session_key, expiry};
    auto encrypted_tgt = encrypt_text(serialize_ticket(tgt), tgs_secret_);

    auto client_key = db_.get_client_long_term_key(client_id);
    auto plain_for_client = c_tgs_session_key + "|" + nonce + "|" + std::to_string(expiry) + "|" + encrypted_tgt;
    auto encrypted_for_client = encrypt_text(plain_for_client, client_key);

    return AsResponse{true, "AS-REP issued", encrypted_for_client};
}

}  // namespace demo
