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

json Client::Get(const std::string& path) const {
    httplib::Client cli(origin_);
    cli.set_connection_timeout(config_.timeout_seconds);
    cli.set_read_timeout(config_.timeout_seconds);
    cli.set_basic_auth(config_.client_id, config_.client_secret);
    return CheckApiResponse(cli.Get(base_path_ + path));
}

json Client::Post(const std::string& path, const std::string& body, const std::string& content_type) const {
    httplib::Client cli(origin_);
    cli.set_connection_timeout(config_.timeout_seconds);
    cli.set_read_timeout(config_.timeout_seconds);
    cli.set_write_timeout(config_.timeout_seconds);
    cli.set_basic_auth(config_.client_id, config_.client_secret);
    return CheckApiResponse(cli.Post(base_path_ + path, body, content_type));
}

std::vector<User> Client::GetUsers() const {
    json j = Get("/api/get-users?" + BuildQuery({{"owner", config_.organization_name}}));
    std::vector<User> users;
    const json& data = j["data"];
    if (data.is_array()) {
        for (const auto& item : data) {
            users.push_back(item.get<User>());
        }
    }
    return users;
}

std::optional<User> Client::GetUser(const std::string& name) const {
    json j = Get("/api/get-user?" + BuildQuery({{"id", config_.organization_name + "/" + name}}));
    const json& data = j["data"];
    if (!data.is_object()) {
        return std::nullopt;
    }
    return data.get<User>();
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
