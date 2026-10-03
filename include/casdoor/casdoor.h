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

#ifndef CASDOOR_CASDOOR_H
#define CASDOOR_CASDOOR_H

#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

namespace casdoor {

// Config holds the settings of a Casdoor application. All values can be copied
// from the application's edit page in the Casdoor UI.
struct Config {
    // Casdoor server URL, like "https://door.casdoor.com". Both http and https work.
    std::string endpoint;
    std::string client_id;
    std::string client_secret;
    // Public certificate (PEM) of the cert used by the application, used to verify JWT tokens.
    std::string certificate;
    std::string organization_name;
    std::string application_name;
    // Timeout of every HTTP request to Casdoor, in seconds.
    int timeout_seconds = 10;
};

// Error is thrown by every Client method that fails, including network errors,
// non-2xx responses, Casdoor API errors and invalid JWT tokens.
class Error : public std::runtime_error {
public:
    explicit Error(const std::string& message, int http_status = 0)
        : std::runtime_error(message), http_status_(http_status) {}

    // HTTP status of the failed response, or 0 if the error didn't come from an HTTP response.
    int http_status() const noexcept { return http_status_; }

private:
    int http_status_;
};

// Token is the response of Casdoor's OAuth token endpoint.
struct Token {
    std::string access_token;
    std::string id_token;
    std::string refresh_token;
    std::string token_type;
    std::string scope;
    int64_t expires_in = 0;
};

// Claims is the payload of a verified Casdoor JWT token.
struct Claims {
    std::string owner;
    std::string name;
    std::string id;
    std::string display_name;
    std::string email;
    std::string phone;
    std::string avatar;
    std::string type;
    bool is_admin = false;

    std::string token_type;
    std::string scope;
    std::string nonce;
    std::string issuer;
    std::string subject;
    std::vector<std::string> audience;
    int64_t issued_at = 0;
    int64_t expires_at = 0;

    // All claims of the token, for fields that don't have a member above.
    nlohmann::json payload;

    bool IsRefreshToken() const { return token_type == "refresh-token"; }
};

// User is a Casdoor user. Only the common fields have members; every other field
// returned by Casdoor is kept in `extra` and sent back unchanged by UpdateUser.
struct User {
    std::string owner;
    std::string name;
    std::string id;
    std::string type;
    std::string password;
    std::string display_name;
    std::string email;
    std::string phone;
    std::string country_code;
    std::string avatar;
    std::string affiliation;
    std::string tag;
    std::string signup_application;
    std::string created_time;
    bool is_admin = false;
    bool is_forbidden = false;

    nlohmann::json extra = nlohmann::json::object();
};

void to_json(nlohmann::json& j, const User& user);
void from_json(const nlohmann::json& j, User& user);

// Client talks to one Casdoor application. It is cheap to copy and its methods
// can be called from multiple threads.
class Client {
public:
    explicit Client(Config config);

    const Config& config() const { return config_; }

    // URL of the Casdoor sign-in page. After signing in, Casdoor redirects the
    // browser to redirect_uri with `code` and `state` query parameters. state
    // defaults to the application name; pass a random value to protect against CSRF.
    std::string GetSigninUrl(const std::string& redirect_uri, const std::string& state = "") const;
    // URL of the Casdoor sign-up page. With enable_password, it's the plain sign-up
    // page of the application; otherwise it's the OAuth sign-up page.
    std::string GetSignupUrl(bool enable_password = true, const std::string& redirect_uri = "") const;
    std::string GetUserProfileUrl(const std::string& user_name, const std::string& access_token = "") const;
    std::string GetMyProfileUrl(const std::string& access_token = "") const;

    // Exchanges the `code` from the sign-in redirect for tokens.
    Token GetOAuthToken(const std::string& code) const;
    Token RefreshOAuthToken(const std::string& refresh_token, const std::string& scope = "") const;
    // Requires the "password" grant type to be enabled in the application.
    Token GetOAuthTokenByPassword(const std::string& username, const std::string& password) const;

    // Verifies the token's signature with Config::certificate, its expiry and its
    // audience, then returns its claims.
    Claims ParseJwtToken(const std::string& token) const;

    // User APIs, authenticated with the client ID and secret.
    // An empty owner means Config::organization_name.
    std::vector<User> GetUsers() const;
    std::optional<User> GetUser(const std::string& name) const;
    // Return true if Casdoor changed something.
    bool AddUser(const User& user) const;
    bool UpdateUser(const User& user) const;
    bool DeleteUser(const User& user) const;

private:
    nlohmann::json Get(const std::string& path) const;
    nlohmann::json Post(const std::string& path, const std::string& body, const std::string& content_type) const;
    Token RequestToken(const std::string& form) const;
    bool ModifyUser(const std::string& action, User user) const;

    Config config_;
    std::string origin_;     // scheme://host[:port]
    std::string base_path_;  // path prefix of the endpoint, usually empty
};

}  // namespace casdoor

#endif  // CASDOOR_CASDOOR_H
