#include "decoy/redaction.h"
#include <fstream>
#include <map>
#include <sstream>
#include <string>
#include "common/logger.h"

namespace hp::decoy {
namespace {

void secure_wipe(std::string& value) {
    volatile char* bytes = value.data();
    for (std::size_t i = 0; i < value.size(); ++i) {
        bytes[i] = '\0';
    }
    value.clear();
}

// Honey Data format: [entry name] on its own line,
// followed by lines of data.
// Search relative to the current working directory first,
// then its parent (build / build-local execution).
std::map<std::string, std::string> load_honey_data() {
    std::map<std::string, std::string> data;

    std::ifstream file("www/decoy/honey_data.txt", std::ios::binary);

    if (!file) {
        file.clear();
        file.open("../www/decoy/honey_data.txt", std::ios::binary);
    }

    if (!file) {
        logger::write(
            "DECOY",
            "honey data file unavailable; using built-in fallback"
        );
        return data;
    }

    std::string line;
    std::string key;

    while (std::getline(file, line)) {
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }

        if (line.size() >= 3 &&
            line.front() == '[' &&
            line.back() == ']') {

            key = line.substr(1, line.size() - 2);

            if (key.empty()) {
                continue;
            }

            data[key] = "";

        } else if (!key.empty()) {
            data[key] += line + "\n";
        }
    }

    return data;
}

std::string fallback_value(const std::string& key) {
    if (key == "secret.txt") {
        return "# TEST SECRET - decoy honey data\n"
               "FLAG=CNU{w3lc0me_t0_th3_s3rv3r}\n"
               "db_user=admin\n"
               "db_password=Spring2026!\n";
    }

    if (key == "admin_token") {
        return "adm-6f1d2c9e8b7a4d3c";
    }

    return "";
}

} // namespace

void redact(SecretStore& store) {
    const auto honey = load_honey_data();

    for (auto& [key, value] : store.entries) {
        secure_wipe(value);

        auto it = honey.find(key);

        value = (it != honey.end() && !it->second.empty())
                    ? it->second
                    : fallback_value(key);
    }

    logger::write(
        "DECOY",
        "redacted " + std::to_string(store.entries.size()) +
        " secret entries"
    );

    // Limitation: this wipes only the selected SecretStore strings,
    // not all transient copies in process memory.
    // This is not full-process redaction.
}

} // namespace hp::decoy
