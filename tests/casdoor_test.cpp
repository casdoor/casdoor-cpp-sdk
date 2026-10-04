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

    std::mt19937 rng(std::random_device{}());
    auto random_name = [&](const std::string& prefix) { return prefix + "_" + std::to_string(rng() % 1000000); };
    const std::string org = config.organization_name;
    const std::string model_text =
        "[request_definition]\nr = sub, obj, act\n\n[policy_definition]\np = sub, obj, act\n\n"
        "[policy_effect]\ne = some(where (p.eft == allow))\n\n"
        "[matchers]\nm = r.sub == p.sub && r.obj == p.obj && r.act == p.act";

    // The same objects as the tests of casdoor-go-sdk, each one is added, listed, got, updated and deleted.
    struct ObjectCase {
        const char* type;
        casdoor::Object object;
        std::string field;
        std::vector<casdoor::Object> (casdoor::Client::*list)() const;
        casdoor::Page (casdoor::Client::*page)(int, int, const casdoor::QueryMap&) const;
        std::optional<casdoor::Object> (casdoor::Client::*get)(const std::string&) const;
        bool (casdoor::Client::*add)(const casdoor::Object&) const;
        bool (casdoor::Client::*update)(const casdoor::Object&) const;
        bool (casdoor::Client::*remove)(const casdoor::Object&) const;
    };
#define CASDOOR_CASE(Type, object, field)                                                                      \
    ObjectCase {                                                                                               \
        #Type, object, field, &casdoor::Client::Get##Type##s, &casdoor::Client::GetPagination##Type##s,        \
            &casdoor::Client::Get##Type, &casdoor::Client::Add##Type, &casdoor::Client::Update##Type,          \
            &casdoor::Client::Delete##Type                                                                     \
    }
    std::vector<ObjectCase> cases = {
        CASDOOR_CASE(Adapter, (casdoor::Object{{"owner", org}, {"user", "adapter"}, {"host", "https://casdoor.org"}}), "user"),
        CASDOOR_CASE(Cert, (casdoor::Object{{"owner", org}, {"displayName", "cert"}, {"scope", "JWT"}, {"type", "x509"},
                                            {"cryptoAlgorithm", "RS256"}, {"bitSize", 4096}, {"expireInYears", 20}}),
                     "displayName"),
        CASDOOR_CASE(Enforcer, (casdoor::Object{{"owner", org}, {"model", "built-in/user-model-built-in"},
                                                {"adapter", "built-in/user-adapter-built-in"}, {"description", "Casdoor"}}),
                     "description"),
        CASDOOR_CASE(Group, (casdoor::Object{{"owner", org}, {"displayName", "group"}}), "displayName"),
        CASDOOR_CASE(Model, (casdoor::Object{{"owner", org}, {"displayName", "model"}, {"modelText", model_text}}),
                     "displayName"),
        CASDOOR_CASE(Payment, (casdoor::Object{{"owner", org}, {"products", {"casdoor"}}, {"price", 10}, {"currency", "USD"}}),
                     "displayName"),
        CASDOOR_CASE(Permission, (casdoor::Object{{"owner", org}, {"users", {org + "/*"}}, {"model", "admin/user-model-built-in"},
                                                  {"resourceType", "Application"}, {"resources", {"app-casbin"}},
                                                  {"actions", {"Read"}}, {"effect", "Allow"}, {"isEnabled", true}}),
                     "description"),
        CASDOOR_CASE(Plan, (casdoor::Object{{"owner", org}, {"currency", "USD"}}), "description"),
        CASDOOR_CASE(Pricing, (casdoor::Object{{"owner", org}, {"application", "app-admin"}}), "description"),
        CASDOOR_CASE(Product, (casdoor::Object{{"owner", org}, {"quantity", 999}, {"state", "Published"},
                                               {"providers", {"provider_payment_dummy"}}, {"currency", "USD"}}),
                     "description"),
        CASDOOR_CASE(Provider, (casdoor::Object{{"owner", org}, {"category", "Captcha"}, {"type", "Default"}}), "displayName"),
        CASDOOR_CASE(Role, (casdoor::Object{{"owner", org}}), "description"),
        CASDOOR_CASE(Subscription, (casdoor::Object{{"owner", org}}), "description"),
        CASDOOR_CASE(Syncer, (casdoor::Object{{"owner", org}, {"organization", org}, {"host", "localhost"}, {"port", 3306},
                                              {"user", "root"}, {"databaseType", "mysql"}, {"database", "syncer_db"},
                                              {"table", "user_table"}, {"syncInterval", 1}}),
                     "host"),
        CASDOOR_CASE(Webhook, (casdoor::Object{{"owner", org}, {"organization", org}}), "url"),
        CASDOOR_CASE(Organization, (casdoor::Object{{"owner", "admin"}, {"passwordType", "plain"}, {"countryCodes", {"US"}},
                                                    {"languages", {"en"}}}),
                     "displayName"),
        CASDOOR_CASE(Application, (casdoor::Object{{"owner", "admin"}, {"organization", org}}), "description"),
    };
#undef CASDOOR_CASE

    for (auto& c : cases) {
        Run((std::string("live: ") + c.type + " crud").c_str(), [&] {
            const std::string name = random_name(c.type);
            casdoor::Object object = c.object;
            object["name"] = name;
            CHECK((client.*c.add)(object));

            bool listed = false;
            for (const auto& item : (client.*c.list)()) {
                listed = listed || item.value("name", "") == name;
            }
            CHECK(listed);
            if (c.object["owner"] != "admin") {
                CHECK((client.*c.page)(1, 100, {}).total > 0);
            }

            const std::string id = object["owner"].get<std::string>() + "/" + name;
            std::optional<casdoor::Object> got = (client.*c.get)(id);
            CHECK(got && got->value("name", "") == name);

            casdoor::Object updated = got ? *got : object;
            updated[c.field] = "https://example.com/updated";
            (client.*c.update)(updated);
            got = (client.*c.get)(id);
            CHECK(got && got->value(c.field, "") == "https://example.com/updated");

            CHECK((client.*c.remove)(updated));
            CHECK(!(client.*c.get)(id).has_value());
        });
    }

    Run("live: session", [&] {
        casdoor::Object session = {{"owner", org}, {"name", random_name("session")}, {"application", "app-built-in"}};
        CHECK(client.AddSession(session));
        CHECK(client.GetSession(session["name"], "app-built-in").has_value());
        CHECK(client.DeleteSession(session));
    });

    Run("live: token", [&] {
        casdoor::Object token = {{"owner", "admin"}, {"name", random_name("token")}, {"application", "app-casbin"},
                                 {"organization", org}, {"user", "admin"}, {"code", "abc"}, {"accessToken", "123456"},
                                 {"expiresIn", 3600}, {"scope", "read"}, {"tokenType", "Bearer"}};
        CHECK(client.AddToken(token));
        token["scope"] = "profile";
        CHECK(client.UpdateTokenForColumns(token, {"scope"}));
        std::optional<casdoor::Object> got = client.GetToken(token["name"]);
        CHECK(got && got->value("scope", "") == "profile");
        CHECK(client.GetPaginationTokens(1, 10).total > 0);
        CHECK(client.DeleteToken(token));
    });

    Run("live: invitation", [&] {
        const std::string code = "TEST" + std::to_string(rng() % 1000000);
        casdoor::Object invitation = {{"owner", org}, {"name", random_name("invitation")}, {"code", code},
                                      {"defaultCode", code}, {"quota", 10}, {"application", "app-casbin"},
                                      {"state", "Active"}};
        CHECK(client.AddInvitation(invitation));
        invitation["displayName"] = "Updated Invitation";
        CHECK(client.UpdateInvitationForColumns(invitation, {"display_name"}));
        std::optional<casdoor::Object> info = client.GetInvitationInfo(code, "app-casbin");
        CHECK(info && info->value("name", "") == invitation["name"]);
        CHECK(client.DeleteInvitation(invitation));
    });

    Run("live: transaction", [&] {
        // a recharge of the organization doesn't need a user balance, so it can be added in CI
        casdoor::Object transaction = {{"owner", org}, {"application", "app-casbin"}, {"domain", "https://casdoor.ai"},
                                       {"category", "Recharge"}, {"type", "Recharge"}, {"tag", "Organization"},
                                       {"amount", 100}, {"currency", "USD"}, {"user", "admin"}, {"state", "Paid"}};
        client.AddTransactionWithDryRun(transaction, true);
        const std::string name = client.AddTransaction(transaction);
        CHECK(!name.empty());
        bool found = false;
        for (const casdoor::Object& item : client.GetUserTransactions("admin")) {
            found = found || item.value("name", "") == name;
        }
        CHECK(found);
        std::optional<casdoor::Object> got = client.GetTransaction(name);
        CHECK(got.has_value());
        if (got) {
            (*got)["displayName"] = "Updated Transaction";
            CHECK(client.UpdateTransaction(*got));
            CHECK(client.DeleteTransaction(*got));
        }
        CHECK(!client.GetTransaction(name).has_value());
    });

    Run("live: record", [&] {
        const std::string name = random_name("Record");
        client.AddRecord({{"owner", org}, {"name", name}, {"organization", org}, {"user", "admin"}, {"action", "test-record"}});

        // reading the records needs the access token of an admin user
        casdoor::Token token = client.GetOAuthTokenByPassword(GetEnv("CASDOOR_TEST_USERNAME", "admin"),
                                                               GetEnv("CASDOOR_TEST_PASSWORD", "123"));
        const casdoor::Client admin_client = client.WithAccessToken(token.access_token);

        bool found = false;
        for (const casdoor::Object& item : admin_client.GetRecords()) {
            found = found || item.value("name", "") == name;
        }
        CHECK(found);
        std::optional<casdoor::Object> got = admin_client.GetRecord(name);
        CHECK(got && got->value("name", "") == name);
        CHECK(!admin_client.GetRecord(name + "_missing").has_value());
    });

    Run("live: order and pay", [&] {
        const std::string product_name = random_name("OrderProduct");
        casdoor::Object product = {{"owner", org}, {"name", product_name}, {"displayName", product_name}, {"quantity", 999},
                                   {"state", "Published"}, {"providers", {"provider_payment_dummy"}}, {"price", 1},
                                   {"currency", "USD"}};
        CHECK(client.AddProduct(product));

        casdoor::Object order = client.PlaceOrder(nlohmann::json::array({{{"name", product_name}, {"quantity", 1}}}), "admin");
        const std::string order_name = order.value("name", "");
        CHECK(!order_name.empty());
        bool listed = false;
        for (const auto& item : client.GetUserOrders("admin")) {
            listed = listed || item.value("name", "") == order_name;
        }
        CHECK(listed);
        CHECK(!client.PayOrder(order_name, "provider_payment_dummy").is_null());
        CHECK(client.CancelOrder(client.BuyProduct(product_name, "provider_payment_dummy", "admin").value("name", "")));

        CHECK(client.DeleteProduct(product));
    });

    Run("live: enforce and policies", [&] {
        const std::string name = random_name("policy");
        casdoor::Object permission = {{"owner", org}, {"name", name}, {"users", {org + "/alice"}},
                                      {"model", "built-in/user-model-built-in"}, {"resourceType", "Application"},
                                      {"resources", {"data1"}}, {"actions", {"read"}}, {"effect", "Allow"},
                                      {"isEnabled", true}};
        CHECK(client.AddPermission(permission));
        const std::string permission_id = org + "/" + name;
        CHECK(client.Enforce(permission_id, "", "", "", "", {org + "/alice", "data1", "read"}));
        CHECK(!client.Enforce(permission_id, "", "", "", "", {org + "/bob", "data1", "read"}));
        auto results = client.BatchEnforce(permission_id, "", "", "", "",
                                           {{org + "/alice", "data1", "read"}, {org + "/bob", "data1", "read"}});
        CHECK(results.size() == 1 && results[0] == std::vector<bool>({true, false}));
        CHECK(client.DeletePermission(permission));

        casdoor::Object model = {{"owner", org}, {"name", name}, {"modelText", model_text}};
        casdoor::Object adapter = {{"owner", org}, {"name", name}, {"table", "casbin_rule_" + name}, {"useSameDb", true}};
        casdoor::Object enforcer = {{"owner", org}, {"name", name}, {"model", org + "/" + name}, {"adapter", org + "/" + name}};
        CHECK(client.AddModel(model));
        CHECK(client.AddAdapter(adapter));
        CHECK(client.AddEnforcer(enforcer));

        casdoor::Object policy = {{"Ptype", "p"}, {"V0", "alice"}, {"V1", "data1"}, {"V2", "read"}};
        CHECK(client.AddPolicy(enforcer, policy));
        CHECK(client.GetPolicies(name).size() == 1);
        CHECK(client.GetFilteredPolicies(permission_id.substr(0, org.size() + 1) + name,
                                         {{{"ptype", "p"}, {"fieldIndex", 0}, {"fieldValues", {"alice"}}}})
                  .size() == 1);
        casdoor::Object new_policy = {{"Ptype", "p"}, {"V0", "alice"}, {"V1", "data1"}, {"V2", "write"}};
        CHECK(client.UpdatePolicy(enforcer, policy, new_policy));
        CHECK(client.RemovePolicy(enforcer, new_policy));
        CHECK(client.GetPolicies(name).empty());

        client.DeleteEnforcer(enforcer);
        client.DeleteAdapter(adapter);
        client.DeleteModel(model);
    });

    Run("live: with access token and logout", [&] {
        casdoor::Token token = client.GetOAuthTokenByPassword(GetEnv("CASDOOR_TEST_USERNAME", "admin"),
                                                               GetEnv("CASDOOR_TEST_PASSWORD", "123"));
        nlohmann::json introspection = client.IntrospectToken(token.access_token);
        CHECK(introspection.value("active", false));

        std::optional<casdoor::User> account = client.WithAccessToken(token.access_token).GetAccount();
        CHECK(account && account->name == GetEnv("CASDOOR_TEST_USERNAME", "admin"));
        // the original client still calls the APIs as the application
        CHECK_THROWS(client.GetAccount());

        client.LogoutCurrentSession(token.access_token);
        client.Logout(client.GetOAuthTokenByPassword(GetEnv("CASDOOR_TEST_USERNAME", "admin"),
                                                     GetEnv("CASDOOR_TEST_PASSWORD", "123"))
                          .access_token);
        CHECK_THROWS(client.Logout(""));
    });

    Run("live: user extra", [&] {
        const std::string name = random_name("user");
        casdoor::User user;
        user.name = name;
        user.email = name + "@example.com";
        user.phone = "202555" + std::to_string(1000 + rng() % 9000);
        user.country_code = "US";
        user.password = "123456";
        CHECK(client.AddUser(user));

        std::optional<casdoor::User> by_email = client.GetUserByEmail(user.email);
        CHECK(by_email && by_email->name == name);
        CHECK(client.GetUserByPhone(user.phone).has_value());
        if (by_email) {
            CHECK(client.GetUserByUserId(by_email->id).has_value());
            casdoor::User updated = *by_email;
            updated.display_name = "Updated by user id";
            CHECK(client.UpdateUserByUserId(org, updated.id, updated));
            CHECK(client.GetUser(name)->display_name == "Updated by user id");
            updated.display_name = "Updated by columns";
            CHECK(client.UpdateUserForColumns(updated, {"displayName"}));
            updated.password = "123456";
            CHECK(client.CheckUserPassword(updated));
            updated.password = "wrong-password";
            CHECK(!client.CheckUserPassword(updated));
        }
        CHECK(client.GetPaginationUsers(1, 10).total > 0);
        CHECK(client.GetSortedUsers("created_time", 1).size() == 1);
        CHECK(client.GetUserCount() > 0);
        CHECK(!client.GetGlobalUsers().empty());
        CHECK(client.DeleteUser(user));

        CHECK(client.GetId("role") == org + "/role");
        CHECK(client.GetId("other/role") == "other/role");
        CHECK(!client.GetOrganizationNames().empty());
        CHECK(!client.GetOrganizationApplications().empty());
        CHECK(!client.GetGlobalCerts().empty());
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
