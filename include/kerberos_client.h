#pragma once

#include <string>

#include "as_server.h"
#include "service_server.h"
#include "tgs_server.h"

namespace demo {

class KerberosClient {
public:
    KerberosClient(std::string client_id, std::string password, std::string tgs_id);

    bool login_and_access_service(
        const AuthenticationServer& as_server,
        const TicketGrantingServer& tgs_server,
        ServiceServer& service,
        const std::string& service_id);

private:
    std::string client_id_;
    std::string password_;
    std::string tgs_id_;
};

}  // namespace demo
