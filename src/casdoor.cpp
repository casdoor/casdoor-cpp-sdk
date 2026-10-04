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

#include "casdoor/casdoor.h"

#ifndef CPPHTTPLIB_OPENSSL_SUPPORT
#define CPPHTTPLIB_OPENSSL_SUPPORT
#endif
#include <httplib.h>

#ifndef JWT_DISABLE_PICOJSON
#define JWT_DISABLE_PICOJSON
#endif
#include <jwt-cpp/traits/nlohmann-json/defaults.h>

#include <algorithm>
#include <utility>

namespace casdoor {

namespace {

using json = nlohmann::json;

std::string UrlEncode(const std::string& value) {
    static const char hex[] = "0123456789ABCDEF";
    std::string out;
    out.reserve(value.size() * 3);
    for (unsigned char c : value) {
        bool unreserved = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
                          c == '-' || c == '_' || c == '.' || c == '~';
        if (unreserved) {
            out += static_cast<char>(c);
        } else {
            out += '%';
            out += hex[c >> 4];
            out += hex[c & 0x0F];
        }
    }
    return out;
}

std::string BuildQuery(const std::vector<std::pair<std::string, std::string>>& params) {
    std::string query;
    for (const auto& param : params) {
        if (!query.empty()) {
            query += '&';
        }
        query += UrlEncode(param.first) + '=' + UrlEncode(param.second);
    }
    return query;
}

std::string GetString(const json& j, const char* key) {
    auto it = j.find(key);
    return it != j.end() && it->is_string() ? it->get<std::string>() : std::string();
}

bool GetBool(const json& j, const char* key) {
    auto it = j.find(key);
    return it != j.end() && it->is_boolean() && it->get<bool>();
}

int64_t GetInt(const json& j, const char* key) {
    auto it = j.find(key);
    return it != j.end() && it->is_number() ? it->get<int64_t>() : 0;
}

json ParseJson(const std::string& body, int http_status) {
    json j = json::parse(body, nullptr, false);
    if (j.is_discarded()) {
        throw Error("Casdoor returned a non-JSON response (HTTP " + std::to_string(http_status) +
                        "): " + body.substr(0, 200),
                    http_status);
    }
    return j;
}

void CheckResult(const httplib::Result& res) {
    if (!res) {
        throw Error("request to Casdoor failed: " + httplib::to_string(res.error()));
    }
}

// Casdoor's API responses look like {"status": "ok" | "error", "msg": "...", "data": ...}.
json CheckApiResponse(const httplib::Result& res) {
    CheckResult(res);
    json j = ParseJson(res->body, res->status);
    if (res->status < 200 || res->status >= 300 || GetString(j, "status") != "ok") {
        std::string msg = GetString(j, "msg");
        if (msg.empty()) {
            msg = "HTTP " + std::to_string(res->status);
        }
        throw Error("Casdoor API error: " + msg, res->status);
    }
    return j;
}

}  // namespace

void to_json(json& j, const User& user) {
    j = user.extra.is_object() ? user.extra : json::object();
    j["owner"] = user.owner;
    j["name"] = user.name;
    j["id"] = user.id;
    j["type"] = user.type;
    if (!user.password.empty()) {
        j["password"] = user.password;
    }
    j["displayName"] = user.display_name;
    j["email"] = user.email;
    j["phone"] = user.phone;
    j["countryCode"] = user.country_code;
    j["avatar"] = user.avatar;
    j["affiliation"] = user.affiliation;
    j["tag"] = user.tag;
    j["signupApplication"] = user.signup_application;
    j["createdTime"] = user.created_time;
    j["isAdmin"] = user.is_admin;
    j["isForbidden"] = user.is_forbidden;
}

void from_json(const json& j, User& user) {
    user.owner = GetString(j, "owner");
    user.name = GetString(j, "name");
    user.id = GetString(j, "id");
    user.type = GetString(j, "type");
    user.password = GetString(j, "password");
    user.display_name = GetString(j, "displayName");
    user.email = GetString(j, "email");
    user.phone = GetString(j, "phone");
    user.country_code = GetString(j, "countryCode");
    user.avatar = GetString(j, "avatar");
    user.affiliation = GetString(j, "affiliation");
    user.tag = GetString(j, "tag");
    user.signup_application = GetString(j, "signupApplication");
    user.created_time = GetString(j, "createdTime");
    user.is_admin = GetBool(j, "isAdmin");
    user.is_forbidden = GetBool(j, "isForbidden");
    user.extra = j.is_object() ? j : json::object();
}

Client::Client(Config config) : config_(std::move(config)) {
    std::string endpoint = config_.endpoint;
    while (!endpoint.empty() && endpoint.back() == '/') {
        endpoint.pop_back();
    }

    auto scheme_end = endpoint.find("://");
    std::string scheme = scheme_end == std::string::npos ? "" : endpoint.substr(0, scheme_end);
    if (scheme != "http" && scheme != "https") {
        throw Error("Casdoor endpoint must start with http:// or https://, got: \"" + config_.endpoint + "\"");
    }

    auto path_start = endpoint.find('/', scheme_end + 3);
    origin_ = endpoint.substr(0, path_start);
    base_path_ = path_start == std::string::npos ? "" : endpoint.substr(path_start);
    config_.endpoint = endpoint;
}

std::string Client::GetSigninUrl(const std::string& redirect_uri, const std::string& state) const {
    return config_.endpoint + "/login/oauth/authorize?" +
           BuildQuery({
               {"client_id", config_.client_id},
               {"response_type", "code"},
               {"redirect_uri", redirect_uri},
               {"scope", "read"},
               {"state", state.empty() ? config_.application_name : state},
           });
}

std::string Client::GetSignupUrl(bool enable_password, const std::string& redirect_uri) const {
    if (enable_password) {
        return config_.endpoint + "/signup/" + UrlEncode(config_.application_name);
    }
    std::string url = GetSigninUrl(redirect_uri);
    url.replace(config_.endpoint.size(), std::string("/login").size(), "/signup");
    return url;
}

std::string Client::GetUserProfileUrl(const std::string& user_name, const std::string& access_token) const {
    std::string url = config_.endpoint + "/users/" + UrlEncode(config_.organization_name) + "/" + UrlEncode(user_name);
    if (!access_token.empty()) {
        url += "?access_token=" + UrlEncode(access_token);
    }
    return url;
}

std::string Client::GetMyProfileUrl(const std::string& access_token) const {
    std::string url = config_.endpoint + "/account";
    if (!access_token.empty()) {
        url += "?access_token=" + UrlEncode(access_token);
    }
    return url;
}

Token Client::GetOAuthToken(const std::string& code) const {
    return RequestToken(BuildQuery({
        {"grant_type", "authorization_code"},
        {"client_id", config_.client_id},
        {"client_secret", config_.client_secret},
        {"code", code},
    }));
}

Token Client::RefreshOAuthToken(const std::string& refresh_token, const std::string& scope) const {
    std::vector<std::pair<std::string, std::string>> params = {
        {"grant_type", "refresh_token"},
        {"client_id", config_.client_id},
        {"client_secret", config_.client_secret},
        {"refresh_token", refresh_token},
    };
    if (!scope.empty()) {
        params.emplace_back("scope", scope);
    }
    return RequestToken(BuildQuery(params));
}

Token Client::GetOAuthTokenByPassword(const std::string& username, const std::string& password) const {
    return RequestToken(BuildQuery({
        {"grant_type", "password"},
        {"client_id", config_.client_id},
        {"client_secret", config_.client_secret},
        {"username", username},
        {"password", password},
    }));
}

Token Client::RequestToken(const std::string& form) const {
    httplib::Client cli(origin_);
    cli.set_connection_timeout(config_.timeout_seconds);
    cli.set_read_timeout(config_.timeout_seconds);
    cli.set_write_timeout(config_.timeout_seconds);

    auto res = cli.Post(base_path_ + "/api/login/oauth/access_token", form, "application/x-www-form-urlencoded");
    CheckResult(res);
    json j = ParseJson(res->body, res->status);

    // Errors come back as {"error": "...", "error_description": "..."} (RFC 6749),
    // older Casdoor versions put "error: ..." into access_token instead.
    std::string error = GetString(j, "error");
    if (!error.empty()) {
        std::string description = GetString(j, "error_description");
        throw Error("Casdoor OAuth error: " + error + (description.empty() ? "" : ": " + description), res->status);
    }

    Token token;
    token.access_token = GetString(j, "access_token");
    if (token.access_token.rfind("error:", 0) == 0) {
        throw Error("Casdoor OAuth error: " + token.access_token.substr(6), res->status);
    }
    if (res->status < 200 || res->status >= 300 || token.access_token.empty()) {
        throw Error("Casdoor OAuth token request failed (HTTP " + std::to_string(res->status) + ")", res->status);
    }
    token.id_token = GetString(j, "id_token");
    token.refresh_token = GetString(j, "refresh_token");
    token.token_type = GetString(j, "token_type");
    token.scope = GetString(j, "scope");
    token.expires_in = GetInt(j, "expires_in");
    return token;
}

Claims Client::ParseJwtToken(const std::string& token) const {
    using traits = jwt::traits::nlohmann_json;

    json payload;
    try {
        auto decoded = jwt::decode<traits>(token);
        const std::string alg = decoded.get_algorithm();
        const std::string& cert = config_.certificate;

        auto verifier = jwt::verify<traits>().leeway(60);
        if (alg == "RS256") {
            verifier.allow_algorithm(jwt::algorithm::rs256(cert));
        } else if (alg == "RS384") {
            verifier.allow_algorithm(jwt::algorithm::rs384(cert));
        } else if (alg == "RS512") {
            verifier.allow_algorithm(jwt::algorithm::rs512(cert));
        } else if (alg == "PS256") {
            verifier.allow_algorithm(jwt::algorithm::ps256(cert));
        } else if (alg == "PS384") {
            verifier.allow_algorithm(jwt::algorithm::ps384(cert));
        } else if (alg == "PS512") {
            verifier.allow_algorithm(jwt::algorithm::ps512(cert));
        } else if (alg == "ES256") {
            verifier.allow_algorithm(jwt::algorithm::es256(cert));
        } else if (alg == "ES384") {
            verifier.allow_algorithm(jwt::algorithm::es384(cert));
        } else if (alg == "ES512") {
            verifier.allow_algorithm(jwt::algorithm::es512(cert));
        } else {
            throw Error("unsupported JWT signing algorithm: \"" + alg + "\"");
        }
        verifier.verify(decoded);

        payload = json::parse(decoded.get_payload());
    } catch (const Error&) {
        throw;
    } catch (const std::exception& e) {
        throw Error(std::string("invalid JWT token: ") + e.what());
    }

    Claims claims;
    auto aud = payload.find("aud");
    if (aud != payload.end() && aud->is_array()) {
        for (const auto& item : *aud) {
            if (item.is_string()) {
                claims.audience.push_back(item.get<std::string>());
            }
        }
    } else if (aud != payload.end() && aud->is_string()) {
        claims.audience.push_back(aud->get<std::string>());
    }
    if (aud != payload.end() &&
        std::find(claims.audience.begin(), claims.audience.end(), config_.client_id) == claims.audience.end()) {
        throw Error("invalid JWT token: audience doesn't contain client ID \"" + config_.client_id + "\"");
    }

    claims.owner = GetString(payload, "owner");
    claims.name = GetString(payload, "name");
    claims.id = GetString(payload, "id");
    claims.display_name = GetString(payload, "displayName");
    claims.email = GetString(payload, "email");
    claims.phone = GetString(payload, "phone");
    claims.avatar = GetString(payload, "avatar");
    claims.type = GetString(payload, "type");
    claims.is_admin = GetBool(payload, "isAdmin");
    claims.token_type = GetString(payload, "tokenType");
    if (claims.token_type.empty()) {
        // The JWT-Custom token format uses "TokenType".
        claims.token_type = GetString(payload, "TokenType");
    }
    claims.scope = GetString(payload, "scope");
    claims.nonce = GetString(payload, "nonce");
    claims.issuer = GetString(payload, "iss");
    claims.subject = GetString(payload, "sub");
    claims.issued_at = GetInt(payload, "iat");
    claims.expires_at = GetInt(payload, "exp");
    claims.payload = std::move(payload);
    return claims;
}

namespace {

// The authentication of the client: the user's access token if set, otherwise the client ID and secret.
httplib::Headers AuthHeaders(const Config& config, const std::string& access_token) {
    httplib::Headers headers(config.custom_headers.begin(), config.custom_headers.end());
    if (!access_token.empty()) {
        headers.emplace("Authorization", "Bearer " + access_token);
    } else {
        headers.emplace(httplib::make_basic_authentication_header(config.client_id, config.client_secret));
    }
    return headers;
}

void SetTimeouts(httplib::Client& cli, int timeout_seconds) {
    cli.set_connection_timeout(timeout_seconds);
    cli.set_read_timeout(timeout_seconds);
    cli.set_write_timeout(timeout_seconds);
}

std::string ApiPath(const std::string& action, const QueryMap& query) {
    QueryMap params;
    for (const auto& param : query) {
        if (!param.second.empty()) {
            params.push_back(param);
        }
    }
    return "/api/" + action + (params.empty() ? "" : "?" + BuildQuery(params));
}

std::string JoinColumns(const std::vector<std::string>& columns) {
    std::string out;
    for (const auto& column : columns) {
        out += (out.empty() ? "" : ",") + column;
    }
    return out;
}

std::vector<Object> ToList(const json& data) {
    std::vector<Object> items;
    if (data.is_array()) {
        for (const auto& item : data) {
            items.push_back(item);
        }
    }
    return items;
}

bool Affected(const json& response) {
    return GetString(response, "data") == "Affected";
}

}  // namespace

json Client::Get(const std::string& path) const {
    httplib::Client cli(origin_);
    SetTimeouts(cli, config_.timeout_seconds);
    return CheckApiResponse(cli.Get(base_path_ + path, AuthHeaders(config_, access_token_)));
}

json Client::Post(const std::string& path, const std::string& body, const std::string& content_type) const {
    httplib::Client cli(origin_);
    SetTimeouts(cli, config_.timeout_seconds);
    return CheckApiResponse(cli.Post(base_path_ + path, AuthHeaders(config_, access_token_), body, content_type));
}

json Client::PostForm(const std::string& action, const QueryMap& query, const QueryMap& form) const {
    httplib::UploadFormDataItems items;
    for (const auto& field : form) {
        items.push_back({field.first, field.second, "", ""});
    }
    httplib::Client cli(origin_);
    SetTimeouts(cli, config_.timeout_seconds);
    return CheckApiResponse(cli.Post(base_path_ + ApiPath(action, query), AuthHeaders(config_, access_token_), items));
}

json Client::DoGet(const std::string& action, const QueryMap& query) const {
    return Get(ApiPath(action, query));
}

json Client::DoPost(const std::string& action, const QueryMap& query, const json& body) const {
    return Post(ApiPath(action, query), body.is_string() ? body.get<std::string>() : body.dump(), "application/json");
}

Client Client::WithAccessToken(const std::string& access_token) const {
    Client client = *this;
    client.access_token_ = access_token;
    return client;
}

std::string Client::GetId(const std::string& name) const {
    return name.find('/') != std::string::npos ? name : config_.organization_name + "/" + name;
}

Token Client::ImpersonateUser(const std::string& username, const std::string& master_password) const {
    return GetOAuthTokenByPassword(username, master_password);
}

json Client::IntrospectToken(const std::string& token, const std::string& token_type_hint) const {
    httplib::Client cli(origin_);
    SetTimeouts(cli, config_.timeout_seconds);
    httplib::Headers headers(config_.custom_headers.begin(), config_.custom_headers.end());
    headers.emplace(httplib::make_basic_authentication_header(config_.client_id, config_.client_secret));
    auto res = cli.Post(base_path_ + "/api/login/oauth/introspect", headers,
                        BuildQuery({{"token", token}, {"token_type_hint", token_type_hint}}),
                        "application/x-www-form-urlencoded");
    CheckResult(res);
    return ParseJson(res->body, res->status);
}

void Client::Logout(const std::string& access_token) const {
    if (access_token.empty()) {
        throw Error("Logout() error: the access token should not be empty");
    }
    WithAccessToken(access_token).DoPost("sso-logout", {{"logoutAll", "true"}}, json(""));
}

void Client::LogoutCurrentSession(const std::string& access_token) const {
    if (access_token.empty()) {
        throw Error("LogoutCurrentSession() error: the access token should not be empty");
    }
    WithAccessToken(access_token).DoPost("sso-logout", {{"logoutAll", "false"}}, json(""));
}

std::vector<Object> Client::GetList(const std::string& action, const QueryMap& query) const {
    return ToList(DoGet(action, query)["data"]);
}

std::optional<Object> Client::GetOne(const std::string& action, const QueryMap& query) const {
    json data = DoGet(action, query)["data"];
    if (!data.is_object()) {
        return std::nullopt;
    }
    return data;
}

Page Client::GetPage(const std::string& action, int p, int page_size, const QueryMap& query) const {
    QueryMap params = query;
    params.emplace_back("p", std::to_string(p));
    params.emplace_back("pageSize", std::to_string(page_size));
    json j = DoGet(action, params);
    Page page;
    page.items = ToList(j["data"]);
    page.total = GetInt(j, "data2");
    return page;
}

bool Client::Modify(const std::string& action, Object object, const std::string& default_owner,
                    const std::vector<std::string>& columns, const std::string& key) const {
    if (!object.is_object()) {
        throw Error(action + ": the object must be a JSON object");
    }
    if (GetString(object, "owner").empty()) {
        object["owner"] = default_owner;
    }
    std::string id = GetString(object, "owner") + "/" + GetString(object, key.c_str());
    return Affected(DoPost(action, {{"id", id}, {"columns", JoinColumns(columns)}}, object));
}

namespace {

std::vector<User> ToUsers(const std::vector<Object>& objects) {
    std::vector<User> users;
    for (const auto& object : objects) {
        users.push_back(object.get<User>());
    }
    return users;
}

std::optional<User> ToUser(const std::optional<Object>& object) {
    if (!object) {
        return std::nullopt;
    }
    return object->get<User>();
}

}  // namespace

std::vector<User> Client::GetUsers() const {
    return ToUsers(GetList("get-users", {{"owner", config_.organization_name}}));
}

std::vector<User> Client::GetGlobalUsers() const {
    return ToUsers(GetList("get-global-users", {}));
}

std::vector<User> Client::GetSortedUsers(const std::string& sorter, int limit) const {
    return ToUsers(GetList("get-sorted-users",
                           {{"owner", config_.organization_name}, {"sorter", sorter}, {"limit", std::to_string(limit)}}));
}

Page Client::GetPaginationUsers(int p, int page_size, const QueryMap& query) const {
    QueryMap params = query;
    params.emplace_back("owner", config_.organization_name);
    return GetPage("get-users", p, page_size, params);
}

int64_t Client::GetUserCount(const std::string& is_online) const {
    json j = DoGet("get-user-count", {{"owner", config_.organization_name}, {"isOnline", is_online}});
    return GetInt(j, "data");
}

std::optional<User> Client::GetUser(const std::string& name) const {
    return ToUser(GetOne("get-user", {{"id", GetId(name)}}));
}

std::optional<User> Client::GetUserByEmail(const std::string& email) const {
    return ToUser(GetOne("get-user", {{"owner", config_.organization_name}, {"email", email}}));
}

std::optional<User> Client::GetUserByPhone(const std::string& phone) const {
    return ToUser(GetOne("get-user", {{"owner", config_.organization_name}, {"phone", phone}}));
}

std::optional<User> Client::GetUserByUserId(const std::string& user_id) const {
    return ToUser(GetOne("get-user", {{"owner", config_.organization_name}, {"userId", user_id}}));
}

std::optional<User> Client::GetAccount() const {
    return ToUser(GetOne("get-account", {}));
}

bool Client::UpdateUserForColumns(const User& user, const std::vector<std::string>& columns) const {
    return Modify("update-user", json(user), config_.organization_name, columns);
}

bool Client::UpdateUserById(const std::string& id, const User& user) const {
    json body = user;
    if (GetString(body, "owner").empty()) {
        body["owner"] = config_.organization_name;
    }
    return Affected(DoPost("update-user", {{"id", id}}, body));
}

bool Client::UpdateUserByUserId(const std::string& owner, const std::string& user_id, const User& user) const {
    return Affected(DoPost("update-user", {{"owner", owner}, {"userId", user_id}}, json(user)));
}

bool Client::CheckUserPassword(const User& user) const {
    json body = user;
    if (GetString(body, "owner").empty()) {
        body["owner"] = config_.organization_name;
    }
    try {
        DoPost("check-user-password", {{"id", GetString(body, "owner") + "/" + user.name}}, body);
        return true;
    } catch (const Error&) {
        return false;
    }
}

bool Client::SetPassword(const std::string& owner, const std::string& name, const std::string& old_password,
                         const std::string& new_password) const {
    PostForm("set-password", {},
             {{"userOwner", owner}, {"userName", name}, {"oldPassword", old_password}, {"newPassword", new_password}});
    return true;
}

// The standard APIs of the object types, see CASDOOR_OBJECT_API in casdoor.h.
#define CASDOOR_OBJECT_IMPL(Type, single, plural, owner, key)                                                  \
    std::vector<Object> Client::Get##Type##s() const { return GetList("get-" plural, {{"owner", owner}}); }   \
    Page Client::GetPagination##Type##s(int p, int page_size, const QueryMap& query) const {                  \
        QueryMap params = query;                                                                               \
        params.emplace_back("owner", owner);                                                                   \
        return GetPage("get-" plural, p, page_size, params);                                                  \
    }                                                                                                          \
    std::optional<Object> Client::Get##Type(const std::string& name) const {                                  \
        std::string id = name.find('/') != std::string::npos ? name : std::string(owner) + "/" + name;        \
        return GetOne("get-" single, {{"id", id}});                                                           \
    }                                                                                                          \
    bool Client::Add##Type(const Object& object) const { return Modify("add-" single, object, owner, {}, key); } \
    bool Client::Update##Type(const Object& object) const {                                                   \
        return Modify("update-" single, object, owner, {}, key);                                              \
    }                                                                                                          \
    bool Client::Update##Type##ForColumns(const Object& object, const std::vector<std::string>& columns) const { \
        return Modify("update-" single, object, owner, columns, key);                                         \
    }                                                                                                          \
    bool Client::Delete##Type(const Object& object) const { return Modify("delete-" single, object, owner, {}, key); }

CASDOOR_OBJECT_IMPL(Adapter, "adapter", "adapters", config_.organization_name, "name")
CASDOOR_OBJECT_IMPL(Application, "application", "applications", std::string("admin"), "name")
CASDOOR_OBJECT_IMPL(Cert, "cert", "certs", config_.organization_name, "name")
CASDOOR_OBJECT_IMPL(Enforcer, "enforcer", "enforcers", config_.organization_name, "name")
CASDOOR_OBJECT_IMPL(Group, "group", "groups", config_.organization_name, "name")
CASDOOR_OBJECT_IMPL(Invitation, "invitation", "invitations", config_.organization_name, "name")
CASDOOR_OBJECT_IMPL(Ldap, "ldap", "ldaps", config_.organization_name, "id")
CASDOOR_OBJECT_IMPL(Model, "model", "models", config_.organization_name, "name")
CASDOOR_OBJECT_IMPL(Order, "order", "orders", config_.organization_name, "name")
CASDOOR_OBJECT_IMPL(Organization, "organization", "organizations", std::string("admin"), "name")
CASDOOR_OBJECT_IMPL(Payment, "payment", "payments", config_.organization_name, "name")
CASDOOR_OBJECT_IMPL(Permission, "permission", "permissions", config_.organization_name, "name")
CASDOOR_OBJECT_IMPL(Plan, "plan", "plans", config_.organization_name, "name")
CASDOOR_OBJECT_IMPL(Pricing, "pricing", "pricings", config_.organization_name, "name")
CASDOOR_OBJECT_IMPL(Product, "product", "products", config_.organization_name, "name")
CASDOOR_OBJECT_IMPL(Provider, "provider", "providers", config_.organization_name, "name")
CASDOOR_OBJECT_IMPL(Role, "role", "roles", config_.organization_name, "name")
CASDOOR_OBJECT_IMPL(Subscription, "subscription", "subscriptions", config_.organization_name, "name")
CASDOOR_OBJECT_IMPL(Syncer, "syncer", "syncers", config_.organization_name, "name")
CASDOOR_OBJECT_IMPL(Token, "token", "tokens", std::string("admin"), "name")
CASDOOR_OBJECT_IMPL(Webhook, "webhook", "webhooks", config_.organization_name, "name")

#undef CASDOOR_OBJECT_IMPL

std::vector<Object> Client::GetSessions() const {
    return GetList("get-sessions", {{"owner", config_.organization_name}});
}

Page Client::GetPaginationSessions(int p, int page_size, const QueryMap& query) const {
    QueryMap params = query;
    params.emplace_back("owner", config_.organization_name);
    return GetPage("get-sessions", p, page_size, params);
}

std::optional<Object> Client::GetSession(const std::string& name, const std::string& application) const {
    return GetOne("get-session", {{"sessionPkId", GetId(name) + "/" + application}});
}

bool Client::AddSession(const Object& session) const {
    return Modify("add-session", session, config_.organization_name);
}

bool Client::UpdateSession(const Object& session) const {
    return Modify("update-session", session, config_.organization_name);
}

bool Client::UpdateSessionForColumns(const Object& session, const std::vector<std::string>& columns) const {
    return Modify("update-session", session, config_.organization_name, columns);
}

bool Client::DeleteSession(const Object& session) const {
    return Modify("delete-session", session, config_.organization_name);
}

std::vector<Object> Client::GetGlobalCerts() const {
    return GetList("get-global-certs", {});
}

std::vector<Object> Client::GetOrganizationNames() const {
    return GetList("get-organization-names", {{"owner", "admin"}});
}

std::vector<Object> Client::GetOrganizationApplications() const {
    return GetList("get-organization-applications", {{"owner", "admin"}, {"organization", config_.organization_name}});
}

std::vector<Object> Client::GetPermissionsByRole(const std::string& role_name) const {
    return GetList("get-permissions-by-role", {{"id", GetId(role_name)}});
}

std::optional<Object> Client::GetInvitationInfo(const std::string& code, const std::string& application_name) const {
    return GetOne("get-invitation-info", {{"applicationId", "admin/" + application_name}, {"code", code}});
}

bool Client::Enforce(const std::string& permission_id, const std::string& model_id, const std::string& resource_id,
                     const std::string& enforcer_id, const std::string& owner, const json& request) const {
    json j = DoPost("enforce",
                    {{"permissionId", permission_id},
                     {"modelId", model_id},
                     {"resourceId", resource_id},
                     {"enforcerId", enforcer_id},
                     {"owner", owner}},
                    request);
    const json& data = j["data"];
    if (!data.is_array()) {
        throw Error("Enforce(): invalid data in the response");
    }
    for (const auto& allowed : data) {
        if (!allowed.is_boolean()) {
            throw Error("Enforce(): invalid data in the response");
        }
        if (allowed.get<bool>()) {
            return true;
        }
    }
    return false;
}

std::vector<std::vector<bool>> Client::BatchEnforce(const std::string& permission_id, const std::string& model_id,
                                                    const std::string& resource_id, const std::string& enforcer_id,
                                                    const std::string& owner, const json& requests) const {
    json j = DoPost("batch-enforce",
                    {{"permissionId", permission_id},
                     {"modelId", model_id},
                     {"resourceId", resource_id},
                     {"enforcerId", enforcer_id},
                     {"owner", owner}},
                    requests);
    std::vector<std::vector<bool>> results;
    for (const auto& items : j["data"]) {
        std::vector<bool> row;
        for (const auto& allowed : items) {
            row.push_back(allowed.is_boolean() && allowed.get<bool>());
        }
        results.push_back(row);
    }
    return results;
}

std::vector<Object> Client::GetPolicies(const std::string& enforcer_name, const std::string& adapter_id) const {
    return GetList("get-policies", {{"id", GetId(enforcer_name)}, {"adapterId", adapter_id}});
}

std::vector<Object> Client::GetFilteredPolicies(const std::string& enforcer_id, const json& filters) const {
    return ToList(DoPost("get-filtered-policies", {{"id", GetId(enforcer_id)}}, filters)["data"]);
}

namespace {

std::string EnforcerId(const Object& enforcer, const std::string& default_owner) {
    std::string owner = GetString(enforcer, "owner");
    return (owner.empty() ? default_owner : owner) + "/" + GetString(enforcer, "name");
}

}  // namespace

bool Client::AddPolicy(const Object& enforcer, const Object& policy) const {
    return Affected(DoPost("add-policy", {{"id", EnforcerId(enforcer, config_.organization_name)}}, policy));
}

bool Client::UpdatePolicy(const Object& enforcer, const Object& old_policy, const Object& new_policy) const {
    return Affected(DoPost("update-policy", {{"id", EnforcerId(enforcer, config_.organization_name)}},
                           json::array({old_policy, new_policy})));
}

bool Client::RemovePolicy(const Object& enforcer, const Object& policy) const {
    return Affected(DoPost("remove-policy", {{"id", EnforcerId(enforcer, config_.organization_name)}}, policy));
}

std::vector<Object> Client::GetUserOrders(const std::string& user_name) const {
    return GetList("get-user-orders", {{"owner", config_.organization_name}, {"user", user_name}});
}

Object Client::PlaceOrder(const json& product_infos, const std::string& user_name) const {
    return DoPost("place-order", {{"owner", config_.organization_name}, {"userName", user_name}},
                  {{"productInfos", product_infos}})["data"];
}

Object Client::PayOrder(const std::string& order_name, const std::string& provider_name) const {
    return DoPost("pay-order", {{"id", GetId(order_name)}, {"providerName", provider_name}}, json(""))["data"];
}

Object Client::BuyProduct(const std::string& name, const std::string& /*provider_name*/,
                          const std::string& user_name) const {
    return PlaceOrder(json::array({{{"name", name}, {"quantity", 1}}}), user_name);
}

bool Client::CancelOrder(const std::string& name) const {
    return Affected(DoPost("cancel-order", {{"id", GetId(name)}}, json("")));
}

std::vector<Object> Client::GetUserPayments(const std::string& user_name) const {
    return GetList("get-user-payments",
                   {{"owner", config_.organization_name}, {"organization", config_.organization_name}, {"user", user_name}});
}

bool Client::NotifyPayment(const Object& payment) const {
    return Modify("notify-payment", payment, config_.organization_name);
}

bool Client::InvoicePayment(const Object& payment) const {
    return Modify("invoice-payment", payment, config_.organization_name);
}

std::vector<Object> Client::GetTransactions() const {
    return GetList("get-transactions", {{"owner", config_.organization_name}});
}

Page Client::GetPaginationTransactions(int p, int page_size, const QueryMap& query) const {
    QueryMap params = query;
    params.emplace_back("owner", config_.organization_name);
    return GetPage("get-transactions", p, page_size, params);
}

std::optional<Object> Client::GetTransaction(const std::string& name) const {
    return GetOne("get-transaction", {{"id", GetId(name)}});
}

std::vector<Object> Client::GetUserTransactions(const std::string& user_name) const {
    return GetList("get-user-transactions", {{"owner", config_.organization_name}, {"user", user_name}});
}

std::string Client::AddTransaction(const Object& transaction) const {
    return AddTransactionWithDryRun(transaction, false);
}

std::string Client::AddTransactionWithDryRun(const Object& transaction, bool dry_run) const {
    json body = transaction;
    if (GetString(body, "owner").empty()) {
        body["owner"] = config_.organization_name;
    }
    json j = DoPost("add-transaction",
                    {{"id", GetString(body, "owner") + "/" + GetString(body, "name")}, {"dryRun", dry_run ? "1" : ""}},
                    body);
    return GetString(j, "data");
}

bool Client::UpdateTransaction(const Object& transaction) const {
    return Modify("update-transaction", transaction, config_.organization_name);
}

bool Client::DeleteTransaction(const Object& transaction) const {
    return Modify("delete-transaction", transaction, config_.organization_name);
}

json Client::GetLdapUsers(const std::string& id) const {
    return DoGet("get-ldap-users", {{"id", GetId(id)}})["data"];
}

json Client::SyncLdapUsers(const std::string& id, const json& users) const {
    return DoPost("sync-ldap-users", {{"id", GetId(id)}}, users)["data"];
}

json Client::SyncLdapUsersFromServer(const std::string& id) const {
    json users = GetLdapUsers(id).value("users", json::array());
    return SyncLdapUsers(id, users.is_null() ? json::array() : users);
}

std::optional<Object> Client::GetResource(const std::string& id) const {
    return GetOne("get-resource", {{"id", GetId(id)}});
}

std::optional<Object> Client::GetResourceEx(const std::string& owner, const std::string& name) const {
    return GetResource(owner + "/" + name);
}

std::vector<Object> Client::GetResources(const std::string& owner, const std::string& user, const std::string& field,
                                         const std::string& value, const std::string& sort_field,
                                         const std::string& sort_order) const {
    return GetList("get-resources", {{"owner", owner},
                                     {"user", user},
                                     {"field", field},
                                     {"value", value},
                                     {"sortField", sort_field},
                                     {"sortOrder", sort_order}});
}

std::vector<Object> Client::GetPaginationResources(const std::string& owner, const std::string& user,
                                                   const std::string& field, const std::string& value, int page_size,
                                                   int page, const std::string& sort_field,
                                                   const std::string& sort_order) const {
    return GetList("get-resources", {{"owner", owner},
                                     {"user", user},
                                     {"field", field},
                                     {"value", value},
                                     {"p", std::to_string(page)},
                                     {"pageSize", std::to_string(page_size)},
                                     {"sortField", sort_field},
                                     {"sortOrder", sort_order}});
}

bool Client::AddResource(const Object& resource) const {
    return Modify("add-resource", resource, config_.organization_name);
}

bool Client::UpdateResource(const Object& resource) const {
    return Modify("update-resource", resource, config_.organization_name);
}

std::pair<std::string, std::string> Client::Upload(const QueryMap& query, const std::string& file_bytes) const {
    httplib::UploadFormDataItems items = {{"file", file_bytes, "file", "application/octet-stream"}};
    httplib::Client cli(origin_);
    SetTimeouts(cli, config_.timeout_seconds);
    json j = CheckApiResponse(
        cli.Post(base_path_ + ApiPath("upload-resource", query), AuthHeaders(config_, access_token_), items));
    return {GetString(j, "data"), GetString(j, "data2")};
}

std::pair<std::string, std::string> Client::UploadResource(const std::string& user, const std::string& tag,
                                                           const std::string& parent,
                                                           const std::string& full_file_path,
                                                           const std::string& file_bytes) const {
    return UploadResourceEx(user, tag, parent, full_file_path, file_bytes, "", "");
}

std::pair<std::string, std::string> Client::UploadResourceEx(const std::string& user, const std::string& tag,
                                                             const std::string& parent,
                                                             const std::string& full_file_path,
                                                             const std::string& file_bytes,
                                                             const std::string& created_time,
                                                             const std::string& description) const {
    return Upload({{"owner", config_.organization_name},
                   {"user", user},
                   {"application", config_.application_name},
                   {"tag", tag},
                   {"parent", parent},
                   {"fullFilePath", full_file_path},
                   {"createdTime", created_time},
                   {"description", description}},
                  file_bytes);
}

bool Client::DeleteResource(const Object& resource) const {
    return DeleteResourceWithTag(resource, "");
}

bool Client::DeleteResourceWithTag(const Object& resource, const std::string& tag) const {
    json body = resource;
    if (GetString(body, "owner").empty()) {
        body["owner"] = config_.organization_name;
    }
    return Affected(DoPost("delete-resource", {{"tag", tag}}, body));
}

std::vector<Object> Client::GetRecords() const {
    return GetList("get-records", {{"owner", config_.organization_name}});
}

Page Client::GetPaginationRecords(int p, int page_size, const QueryMap& query) const {
    QueryMap params = query;
    params.emplace_back("owner", config_.organization_name);
    return GetPage("get-records", p, page_size, params);
}

std::optional<Object> Client::GetRecord(const std::string& name) const {
    return GetOne("get-record", {{"id", GetId(name)}});
}

bool Client::AddRecord(Object record) const {
    if (GetString(record, "owner").empty()) {
        record["owner"] = config_.organization_name;
    }
    if (GetString(record, "organization").empty()) {
        record["organization"] = config_.organization_name;
    }
    return Affected(DoPost("add-record", {}, record));
}

void Client::SendEmail(const std::string& title, const std::string& content, const std::string& sender,
                       const std::vector<std::string>& receivers) const {
    SendEmailByProvider(title, content, sender, "", receivers);
}

void Client::SendEmailByProvider(const std::string& title, const std::string& content, const std::string& sender,
                                 const std::string& provider, const std::vector<std::string>& receivers) const {
    DoPost("send-email", {{"provider", provider}},
           {{"title", title}, {"content", content}, {"sender", sender}, {"receivers", receivers}});
}

void Client::SendSms(const std::string& content, const std::vector<std::string>& receivers) const {
    SendSmsByProvider(content, "", receivers);
}

void Client::SendSmsByProvider(const std::string& content, const std::string& provider,
                               const std::vector<std::string>& receivers) const {
    DoPost("send-sms", {{"provider", provider}}, {{"content", content}, {"receivers", receivers}});
}

void Client::SendNotification(const std::string& content, const std::string& recipient) const {
    DoPost("send-notification", {}, {{"content", content}, {"recipient", recipient}});
}

json Client::MfaInitiate(const std::string& owner, const std::string& mfa_type, const std::string& name) const {
    return PostForm("mfa/setup/initiate", {}, {{"owner", owner}, {"mfaType", mfa_type}, {"name", name}})["data"];
}

json Client::MfaVerify(const std::string& owner, const std::string& mfa_type, const std::string& name,
                       const std::string& secret, const std::string& passcode) const {
    return PostForm("mfa/setup/verify", {},
                    {{"owner", owner}, {"mfaType", mfa_type}, {"name", name}, {"secret", secret}, {"passcode", passcode}});
}

json Client::MfaEnable(const std::string& owner, const std::string& mfa_type, const std::string& name,
                       const std::string& secret, const std::string& recovery_code) const {
    return PostForm("mfa/setup/enable", {},
                    {{"owner", owner},
                     {"mfaType", mfa_type},
                     {"name", name},
                     {"secret", secret},
                     {"recoveryCode", recovery_code}});
}

void Client::MfaSetPreferred(const std::string& owner, const std::string& mfa_type, const std::string& name,
                             const std::string& secret) const {
    PostForm("set-preferred-mfa", {}, {{"owner", owner}, {"mfaType", mfa_type}, {"name", name}, {"secret", secret}});
}

void Client::MfaDelete(const std::string& owner, const std::string& name) const {
    DoPost("delete-mfa", {{"owner", owner}, {"name", name}}, json(""));
}

bool Client::AddUser(const User& user) const {
    return ModifyUser("add-user", user);
}

bool Client::UpdateUser(const User& user) const {
    return ModifyUser("update-user", user);
}

bool Client::DeleteUser(const User& user) const {
    return ModifyUser("delete-user", user);
}

bool Client::ModifyUser(const std::string& action, User user) const {
    if (user.owner.empty()) {
        user.owner = config_.organization_name;
    }
    if (user.name.empty()) {
        throw Error("user name is empty");
    }

    json body = user;
    json j = Post("/api/" + action + "?" + BuildQuery({{"id", user.owner + "/" + user.name}}), body.dump(),
                  "application/json");
    return GetString(j, "data") == "Affected";
}

}  // namespace casdoor
