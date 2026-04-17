#include "messages.h"

#include <sstream>
#include <stdexcept>
#include <vector>

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

std::string serialize_ticket(const Ticket& ticket) {
    return ticket.client_id + "|" + ticket.server_id + "|" + ticket.session_key + "|" + std::to_string(ticket.expires_at);
}

Ticket deserialize_ticket(const std::string& data) {
    auto parts = split_pipe(data);
    if (parts.size() != 4) {
        throw std::runtime_error("Malformed ticket");
    }

    Ticket ticket;
    ticket.client_id = parts[0];
    ticket.server_id = parts[1];
    ticket.session_key = parts[2];
    ticket.expires_at = std::stol(parts[3]);
    return ticket;
}

std::string serialize_authenticator(const Authenticator& auth) {
    return auth.client_id + "|" + std::to_string(auth.timestamp);
}

Authenticator deserialize_authenticator(const std::string& data) {
    auto parts = split_pipe(data);
    if (parts.size() != 2) {
        throw std::runtime_error("Malformed authenticator");
    }

    Authenticator auth;
    auth.client_id = parts[0];
    auth.timestamp = std::stol(parts[1]);
    return auth;
}

}  // namespace demo
