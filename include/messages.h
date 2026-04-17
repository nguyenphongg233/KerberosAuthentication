#pragma once

#include <string>

namespace demo {

struct Ticket {
    std::string client_id;
    std::string server_id;
    std::string session_key;
    long expires_at;
};

struct Authenticator {
    std::string client_id;
    long timestamp;
};

std::string serialize_ticket(const Ticket& ticket);
Ticket deserialize_ticket(const std::string& data);

std::string serialize_authenticator(const Authenticator& auth);
Authenticator deserialize_authenticator(const std::string& data);

}  // namespace demo
