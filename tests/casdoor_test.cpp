/*
 * Copyright 2026 The Casdoor Authors. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// Offline tests always run. Tests against a real Casdoor server run when
// CASDOOR_TEST_ENDPOINT is set, with the same test data as casdoor-go-sdk.
// See .github/workflows/ci.yml for how to start that server.

#include "casdoor/casdoor.h"

#define JWT_DISABLE_PICOJSON
#include <jwt-cpp/traits/nlohmann-json/defaults.h>

#include <chrono>
#include <cstdlib>
#include <fstream>
#include <functional>
#include <iostream>
#include <random>
#include <sstream>

namespace {

int g_failures = 0;
int g_checks = 0;

#define CHECK(cond)                                                                          \
    do {                                                                                     \
        ++g_checks;                                                                          \
        if (!(cond)) {                                                                       \
            ++g_failures;                                                                    \
            std::cerr << __FILE__ << ":" << __LINE__ << ": CHECK failed: " #cond << std::endl; \
        }                                                                                    \
    } while (0)

#define CHECK_THROWS(expr)                                                                          \
    do {                                                                                            \
        ++g_checks;                                                                                 \
        bool thrown = false;                                                                        \
        try {                                                                                       \
            (void)(expr);                                                                           \
        } catch (const casdoor::Error&) {                                                           \
            thrown = true;                                                                          \
        }                                                                                           \
        if (!thrown) {                                                                              \
            ++g_failures;                                                                           \
            std::cerr << __FILE__ << ":" << __LINE__ << ": expected casdoor::Error: " #expr << std::endl; \
        }                                                                                           \
    } while (0)

std::string ReadFile(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        std::cerr << "cannot open " << path << std::endl;
        std::exit(1);
    }
    std::stringstream ss;
    ss << file.rdbuf();
    return ss.str();
}

std::string GetEnv(const char* key, const std::string& default_value) {
    const char* value = std::getenv(key);
    return value != nullptr && *value != '\0' ? value : default_value;
}

void Run(const char* name, const std::function<void()>& test) {
    int failures = g_failures;
    try {
        test();
    } catch (const std::exception& e) {
        ++g_failures;
        std::cerr << name << ": unexpected exception: " << e.what() << std::endl;
    }
    std::cout << (g_failures == failures ? "PASS " : "FAIL ") << name << std::endl;
}

casdoor::Config OfflineConfig() {
    casdoor::Config config;
    config.endpoint = "https://door.example.com/";
    config.client_id = "client-id";
    config.client_secret = "client-secret";
    config.certificate = ReadFile("data/test.crt");
    config.organization_name = "my org";
    config.application_name = "app-test";
    return config;
}

std::string SignToken(const std::string& private_key,
                      std::chrono::system_clock::time_point expires_at,
                      const std::string& audience = "client-id") {
    auto now = std::chrono::system_clock::now();
    return jwt::create<jwt::traits::nlohmann_json>()
        .set_type("JWT")
        .set_issuer("https://door.example.com")
        .set_subject("user-id")
        .set_audience(std::vector<nlohmann::json>{audience})
        .set_issued_at(now)
        .set_expires_at(expires_at)
        .set_payload_claim("owner", "my org")
        .set_payload_claim("name", "alice")
        .set_payload_claim("displayName", "Alice")
        .set_payload_claim("email", "alice@example.com")
        .set_payload_claim("isAdmin", true)
        .set_payload_claim("tokenType", "access-token")
        .set_payload_claim("signupApplication", "app-test")
        .sign(jwt::algorithm::rs256("", private_key));
}

void OfflineTests() {
    const casdoor::Client client(OfflineConfig());
    const std::string key = ReadFile("data/test.key");
    const auto in_an_hour = std::chrono::system_clock::now() + std::chrono::hours(1);

    Run("signin url", [&] {
        CHECK(client.GetSigninUrl("http://localhost:8080/callback?a=1&b=2") ==
              "https://door.example.com/login/oauth/authorize?client_id=client-id&response_type=code"
              "&redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Fcallback%3Fa%3D1%26b%3D2&scope=read&state=app-test");
        CHECK(client.GetSigninUrl("http://localhost/cb", "xyz").find("&state=xyz") != std::string::npos);
    });

    Run("signup and profile urls", [&] {
        CHECK(client.GetSignupUrl() == "https://door.example.com/signup/app-test");
        CHECK(client.GetSignupUrl(false, "http://localhost/cb").rfind(
                  "https://door.example.com/signup/oauth/authorize?client_id=client-id", 0) == 0);
        CHECK(client.GetUserProfileUrl("alice", "tok") == "https://door.example.com/users/my%20org/alice?access_token=tok");
        CHECK(client.GetMyProfileUrl() == "https://door.example.com/account");
    });

    Run("endpoint validation", [&] {
        casdoor::Config config = OfflineConfig();
        config.endpoint = "door.example.com";
        CHECK_THROWS(casdoor::Client{config});
        config.endpoint = "http://door.example.com/casdoor/";
        CHECK(casdoor::Client(config).GetMyProfileUrl() == "http://door.example.com/casdoor/account");
    });

    Run("parse valid token", [&] {
        casdoor::Claims claims = client.ParseJwtToken(SignToken(key, in_an_hour));
        CHECK(claims.owner == "my org");
        CHECK(claims.name == "alice");
        CHECK(claims.display_name == "Alice");
        CHECK(claims.email == "alice@example.com");
        CHECK(claims.is_admin);
        CHECK(claims.token_type == "access-token");
        CHECK(!claims.IsRefreshToken());
        CHECK(claims.subject == "user-id");
        CHECK(claims.audience == std::vector<std::string>{"client-id"});
        CHECK(claims.expires_at > 0);
        CHECK(claims.payload["signupApplication"] == "app-test");
    });

    Run("parse es256 token", [&] {
        casdoor::Config config = OfflineConfig();
        config.certificate = ReadFile("data/ec.crt");
        std::string token = jwt::create<jwt::traits::nlohmann_json>()
                                .set_payload_claim("name", "bob")
                                .set_expires_at(in_an_hour)
                                .sign(jwt::algorithm::es256("", ReadFile("data/ec.key")));
        CHECK(casdoor::Client(config).ParseJwtToken(token).name == "bob");
    });

    Run("reject tampered token", [&] {
        std::string token = SignToken(key, in_an_hour);
        auto first_dot = token.find('.');
        auto second_dot = token.find('.', first_dot + 1);
        std::string payload = jwt::base::decode<jwt::alphabet::base64url>(
            jwt::base::pad<jwt::alphabet::base64url>(token.substr(first_dot + 1, second_dot - first_dot - 1)));
        auto pos = payload.find("alice");
        payload.replace(pos, 5, "admin");
        std::string forged = token.substr(0, first_dot + 1) +
                             jwt::base::trim<jwt::alphabet::base64url>(
                                 jwt::base::encode<jwt::alphabet::base64url>(payload)) +
                             token.substr(second_dot);
        CHECK_THROWS(client.ParseJwtToken(forged));
    });

    Run("reject token signed by another key", [&] {
        CHECK_THROWS(client.ParseJwtToken(SignToken(ReadFile("data/other.key"), in_an_hour)));
    });

    Run("reject expired token", [&] {
        CHECK_THROWS(client.ParseJwtToken(SignToken(key, std::chrono::system_clock::now() - std::chrono::hours(1))));
    });

    Run("reject token for another application", [&] {
        CHECK_THROWS(client.ParseJwtToken(SignToken(key, in_an_hour, "another-client-id")));
    });

    Run("reject unsigned and malformed tokens", [&] {
        std::string unsigned_token = jwt::create<jwt::traits::nlohmann_json>()
                                         .set_payload_claim("name", "alice")
                                         .sign(jwt::algorithm::none{});
        CHECK_THROWS(client.ParseJwtToken(unsigned_token));
        CHECK_THROWS(client.ParseJwtToken("not a token"));
        CHECK_THROWS(client.ParseJwtToken(""));
    });

    Run("user json keeps unknown fields", [&] {
        auto j = nlohmann::json::parse(R"({"owner":"o","name":"n","displayName":"N","isAdmin":true,
                                           "score":42,"address":["x"],"password":"***"})");
        casdoor::User user = j.get<casdoor::User>();
        CHECK(user.display_name == "N");
        CHECK(user.is_admin);
        user.display_name = "M";
        nlohmann::json out = user;
        CHECK(out["displayName"] == "M");
        CHECK(out["score"] == 42);
        CHECK(out["address"] == nlohmann::json::array({"x"}));
        CHECK(out["password"] == "***");

        casdoor::User fresh;
        fresh.name = "new";
        nlohmann::json fresh_json = fresh;
        CHECK(!fresh_json.contains("password"));
    });

    Run("network error", [&] {
        casdoor::Config config = OfflineConfig();
        config.endpoint = "http://127.0.0.1:1";
        config.timeout_seconds = 2;
        casdoor::Client unreachable(config);
        CHECK_THROWS(unreachable.GetOAuthToken("code"));
        CHECK_THROWS(unreachable.GetUsers());
    });
}

void LiveTests(const std::string& endpoint) {
    casdoor::Config config;
    config.endpoint = endpoint;
    config.client_id = GetEnv("CASDOOR_TEST_CLIENT_ID", "casdoor-go-sdk-ci-client");
    config.client_secret = GetEnv("CASDOOR_TEST_CLIENT_SECRET", "casdoor-go-sdk-ci-secret");
    // Casdoor generates a new built-in cert on first start, so it has to be
    // fetched from the server, like .github/workflows/ci.yml does.
    config.certificate = ReadFile(GetEnv("CASDOOR_TEST_CERTIFICATE_FILE", "data/casdoor.crt"));
    config.organization_name = GetEnv("CASDOOR_TEST_ORGANIZATION", "casbin");
    config.application_name = GetEnv("CASDOOR_TEST_APPLICATION", "app-casibase");
    const casdoor::Client client(config);

    Run("live: password grant, parse and refresh token", [&] {
        casdoor::Token token = client.GetOAuthTokenByPassword(GetEnv("CASDOOR_TEST_USERNAME", "admin"),
                                                               GetEnv("CASDOOR_TEST_PASSWORD", "123"));
        CHECK(!token.access_token.empty());
        CHECK(!token.refresh_token.empty());
        CHECK(token.expires_in > 0);

        casdoor::Claims claims = client.ParseJwtToken(token.access_token);
        CHECK(claims.name == GetEnv("CASDOOR_TEST_USERNAME", "admin"));
        CHECK(!claims.owner.empty());
        CHECK(claims.token_type == "access-token");

        casdoor::Token refreshed = client.RefreshOAuthToken(token.refresh_token);
        CHECK(client.ParseJwtToken(refreshed.access_token).name == claims.name);
    });

    Run("live: oauth errors", [&] {
        try {
            client.GetOAuthToken("invalid-code");
            CHECK(false);
        } catch (const casdoor::Error& e) {
            CHECK(std::string(e.what()).find("invalid_grant") != std::string::npos);
        }
        CHECK_THROWS(client.GetOAuthTokenByPassword("admin", "wrong-password"));
    });

    Run("live: wrong client secret", [&] {
        casdoor::Config wrong = config;
        wrong.client_secret = "wrong";
        CHECK_THROWS(casdoor::Client(wrong).GetUsers());
    });

    Run("live: user crud", [&] {
        std::mt19937 rng(std::random_device{}());
        const std::string name = "cpp_sdk_" + std::to_string(rng() % 1000000);

        casdoor::User user;
        user.name = name;
        user.display_name = "C++ SDK test";
        user.password = "123456";
        user.email = name + "@example.com";
        CHECK(client.AddUser(user));

        std::optional<casdoor::User> got = client.GetUser(name);
        CHECK(got.has_value());
        if (got) {
            CHECK(got->display_name == "C++ SDK test");
            CHECK(got->owner == config.organization_name);

            got->display_name = "C++ SDK test updated";
            CHECK(client.UpdateUser(*got));
            std::optional<casdoor::User> updated = client.GetUser(name);
            CHECK(updated && updated->display_name == "C++ SDK test updated");
            CHECK(updated && updated->email == name + "@example.com");
        }

        bool listed = false;
        for (const auto& u : client.GetUsers()) {
            listed = listed || u.name == name;
        }
        CHECK(listed);

        CHECK(client.DeleteUser(user));
        CHECK(!client.GetUser(name).has_value());
    });
}

}  // namespace

int main() {
    OfflineTests();

    std::string endpoint = GetEnv("CASDOOR_TEST_ENDPOINT", "");
    if (endpoint.empty()) {
        std::cout << "CASDOOR_TEST_ENDPOINT is not set, skipping tests against a Casdoor server" << std::endl;
    } else {
        LiveTests(endpoint);
    }

    std::cout << g_checks - g_failures << "/" << g_checks << " checks passed" << std::endl;
    return g_failures == 0 ? 0 : 1;
}
