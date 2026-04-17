#include <iostream>
#include <string>
#include <unordered_map>

#include "as_server.h"
#include "kdc_database.h"
#include "kerberos_client.h"
#include "service_server.h"
#include "tgs_server.h"

int main(int argc, char* argv[]) {
    using namespace demo;

    auto print_usage = []() {
        std::cout
            << "Usage:\n"
            << "  kerberos_demo [--scenario all|success|wrong-password|unknown-service|custom]"
               " [--user <id>] [--password <pwd>] [--service <service-id>]\n\n"
            << "Examples:\n"
            << "  kerberos_demo --scenario all\n"
            << "  kerberos_demo --scenario success\n"
            << "  kerberos_demo --scenario wrong-password\n"
            << "  kerberos_demo --scenario unknown-service\n"
            << "  kerberos_demo --scenario custom --user alice --password alice_password_123 --service mail-service\n";
    };

    std::string scenario = "all";
    std::string custom_user = "alice";
    std::string custom_password = "alice_password_123";
    std::string custom_service = "mail-service";

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--scenario" && i + 1 < argc) {
            scenario = argv[++i];
        } else if (arg == "--user" && i + 1 < argc) {
            custom_user = argv[++i];
        } else if (arg == "--password" && i + 1 < argc) {
            custom_password = argv[++i];
        } else if (arg == "--service" && i + 1 < argc) {
            custom_service = argv[++i];
        } else if (arg == "--help" || arg == "-h") {
            print_usage();
            return 0;
        } else {
            std::cout << "Unknown argument: " << arg << "\n\n";
            print_usage();
            return 1;
        }
    }

    std::cout << "===== Kerberos Protocol Demo (Educational) =====\n";

    KdcDatabase db;
    db.add_client("alice", "alice_password_123");

    const std::string tgs_secret = "TGS_SECRET_KEY";
    const std::string mail_service_secret = "MAIL_SERVICE_SECRET";

    AuthenticationServer as_server(db, tgs_secret, 300);
    TicketGrantingServer tgs_server(tgs_secret, { {"mail-service", mail_service_secret} }, 300);
    ServiceServer mail_service(mail_service_secret);

    auto run = [&](const std::string& title,
                   const std::string& user,
                   const std::string& password,
                   const std::string& service_id) {
        std::cout << "\n--- " << title << " ---\n";
        KerberosClient client(user, password, "krbtgt");
        bool ok = client.login_and_access_service(as_server, tgs_server, mail_service, service_id);
        std::cout << title << " result: " << (ok ? "SUCCESS" : "FAIL") << "\n";
        return ok;
    };

    if (scenario == "all") {
        run("Scenario: Successful Login", "alice", "alice_password_123", "mail-service");
        run("Scenario: Wrong Password", "alice", "wrong_password", "mail-service");
        run("Scenario: Unknown Service", "alice", "alice_password_123", "chat-service");
    } else if (scenario == "success") {
        run("Scenario: Successful Login", "alice", "alice_password_123", "mail-service");
    } else if (scenario == "wrong-password") {
        run("Scenario: Wrong Password", "alice", "wrong_password", "mail-service");
    } else if (scenario == "unknown-service") {
        run("Scenario: Unknown Service", "alice", "alice_password_123", "chat-service");
    } else if (scenario == "custom") {
        run("Scenario: Custom", custom_user, custom_password, custom_service);
    } else {
        std::cout << "Invalid scenario: " << scenario << "\n\n";
        print_usage();
        return 1;
    }

    std::cout << "\nDone.\n";
    return 0;
}
