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
#include <map>
#include <optional>
#include <utility>
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
    // HTTP headers added to all the API requests, e.g. "Accept-Language"
    std::map<std::string, std::string> custom_headers;
};

// Object is a Casdoor object (role, group, product, ...) as JSON, with the same fields as
// the structs of casdoor-go-sdk, e.g. {"owner": "my-org", "name": "admin", "users": [...]}.
using Object = nlohmann::json;

// QueryMap holds extra query parameters, e.g. {{"field", "name"}, {"value", "abc"}, {"sortField", "createdTime"}}.
using QueryMap = std::vector<std::pair<std::string, std::string>>;

// Page is a page of objects returned by the GetPagination*() methods.
struct Page {
    std::vector<Object> items;
    int64_t total = 0;
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

    // Returns a new client that calls the APIs as the user who owns the access token (Authorization: Bearer)
    // instead of as the application, with the user's own permissions. This client is not changed.
    Client WithAccessToken(const std::string& access_token) const;

    // Returns name as is if it's already an "owner/name" ID, otherwise prefixes it with the organization.
    std::string GetId(const std::string& name) const;

    // Signs in as any user of the organization with the organization's master password.
    Token ImpersonateUser(const std::string& username, const std::string& master_password) const;
    // Introspects the token (RFC 7662), the result has "active" and the claims of the token.
    nlohmann::json IntrospectToken(const std::string& token, const std::string& token_type_hint = "access_token") const;
    // Signs the user out of all the applications and devices (SSO logout).
    void Logout(const std::string& access_token) const;
    // Only signs the user out of the session of the access token.
    void LogoutCurrentSession(const std::string& access_token) const;

    // User APIs, authenticated with the client ID and secret, or with the access token of WithAccessToken().
    // An empty owner means Config::organization_name. The modifying methods return true if Casdoor changed something.
    std::vector<User> GetUsers() const;
    std::vector<User> GetGlobalUsers() const;
    std::vector<User> GetSortedUsers(const std::string& sorter, int limit) const;
    Page GetPaginationUsers(int p, int page_size, const QueryMap& query = {}) const;
    int64_t GetUserCount(const std::string& is_online = "") const;
    std::optional<User> GetUser(const std::string& name) const;
    std::optional<User> GetUserByEmail(const std::string& email) const;
    std::optional<User> GetUserByPhone(const std::string& phone) const;
    std::optional<User> GetUserByUserId(const std::string& user_id) const;
    // Gets the user of the access token, i.e. "who am I", the client must be created by WithAccessToken().
    std::optional<User> GetAccount() const;
    bool AddUser(const User& user) const;
    bool UpdateUser(const User& user) const;
    bool UpdateUserForColumns(const User& user, const std::vector<std::string>& columns) const;
    // Updates the user identified by its "owner/name" ID, so the user can be renamed.
    bool UpdateUserById(const std::string& id, const User& user) const;
    // Updates the user identified by its user ID (the "id" field of the user).
    bool UpdateUserByUserId(const std::string& owner, const std::string& user_id, const User& user) const;
    bool DeleteUser(const User& user) const;
    // Checks if user.password is the password of the user.
    bool CheckUserPassword(const User& user) const;
    bool SetPassword(const std::string& owner, const std::string& name, const std::string& old_password,
                     const std::string& new_password) const;

    // The standard APIs of each object type, e.g. GetRoles(), GetPaginationRoles(), GetRole(), AddRole(),
    // UpdateRole(), UpdateRoleForColumns() and DeleteRole(). The name of Get*() can be an "owner/name" ID.
#define CASDOOR_OBJECT_API(Type)                                                                        \
    std::vector<Object> Get##Type##s() const;                                                          \
    Page GetPagination##Type##s(int p, int page_size, const QueryMap& query = {}) const;                \
    std::optional<Object> Get##Type(const std::string& name) const;                                    \
    bool Add##Type(const Object& object) const;                                                         \
    bool Update##Type(const Object& object) const;                                                      \
    bool Update##Type##ForColumns(const Object& object, const std::vector<std::string>& columns) const; \
    bool Delete##Type(const Object& object) const;
    CASDOOR_OBJECT_API(Adapter)
    CASDOOR_OBJECT_API(Application)
    CASDOOR_OBJECT_API(Cert)
    CASDOOR_OBJECT_API(Enforcer)
    CASDOOR_OBJECT_API(Group)
    CASDOOR_OBJECT_API(Invitation)
    CASDOOR_OBJECT_API(Ldap)
    CASDOOR_OBJECT_API(Model)
    CASDOOR_OBJECT_API(Order)
    CASDOOR_OBJECT_API(Organization)
    CASDOOR_OBJECT_API(Payment)
    CASDOOR_OBJECT_API(Permission)
    CASDOOR_OBJECT_API(Plan)
    CASDOOR_OBJECT_API(Pricing)
    CASDOOR_OBJECT_API(Product)
    CASDOOR_OBJECT_API(Provider)
    CASDOOR_OBJECT_API(Role)
    CASDOOR_OBJECT_API(Subscription)
    CASDOOR_OBJECT_API(Syncer)
    CASDOOR_OBJECT_API(Token)
    CASDOOR_OBJECT_API(Webhook)
#undef CASDOOR_OBJECT_API

    std::vector<Object> GetSessions() const;
    Page GetPaginationSessions(int p, int page_size, const QueryMap& query = {}) const;
    std::optional<Object> GetSession(const std::string& name, const std::string& application) const;
    bool AddSession(const Object& session) const;
    bool UpdateSession(const Object& session) const;
    bool UpdateSessionForColumns(const Object& session, const std::vector<std::string>& columns) const;
    bool DeleteSession(const Object& session) const;

    std::vector<Object> GetGlobalCerts() const;
    std::vector<Object> GetOrganizationNames() const;
    std::vector<Object> GetOrganizationApplications() const;
    std::vector<Object> GetPermissionsByRole(const std::string& role_name) const;
    std::optional<Object> GetInvitationInfo(const std::string& code, const std::string& application_name) const;

    // Checks the request (e.g. {"alice", "data1", "read"}) against a permission, a model, a resource, an enforcer
    // or all the permissions of an owner, it's allowed if any of the matched permissions allows it.
    bool Enforce(const std::string& permission_id, const std::string& model_id, const std::string& resource_id,
                 const std::string& enforcer_id, const std::string& owner, const nlohmann::json& request) const;
    std::vector<std::vector<bool>> BatchEnforce(const std::string& permission_id, const std::string& model_id,
                                                const std::string& resource_id, const std::string& enforcer_id,
                                                const std::string& owner, const nlohmann::json& requests) const;

    // A policy is {"Ptype": "p", "V0": "alice", "V1": "data1", "V2": "read"}.
    std::vector<Object> GetPolicies(const std::string& enforcer_name, const std::string& adapter_id = "") const;
    // A filter is {"ptype": "p", "fieldIndex": 0, "fieldValues": ["alice"]}.
    std::vector<Object> GetFilteredPolicies(const std::string& enforcer_id, const nlohmann::json& filters) const;
    bool AddPolicy(const Object& enforcer, const Object& policy) const;
    bool UpdatePolicy(const Object& enforcer, const Object& old_policy, const Object& new_policy) const;
    bool RemovePolicy(const Object& enforcer, const Object& policy) const;

    std::vector<Object> GetUserOrders(const std::string& user_name) const;
    // Places an order of the products, e.g. [{"name": "product", "quantity": 1}], for the user.
    Object PlaceOrder(const nlohmann::json& product_infos, const std::string& user_name = "") const;
    // Creates a payment of the order with the payment provider.
    Object PayOrder(const std::string& order_name, const std::string& provider_name) const;
    Object BuyProduct(const std::string& name, const std::string& provider_name, const std::string& user_name = "") const;
    bool CancelOrder(const std::string& name) const;

    std::vector<Object> GetUserPayments(const std::string& user_name) const;
    bool NotifyPayment(const Object& payment) const;
    bool InvoicePayment(const Object& payment) const;

    std::vector<Object> GetTransactions() const;
    Page GetPaginationTransactions(int p, int page_size, const QueryMap& query = {}) const;
    std::optional<Object> GetTransaction(const std::string& name) const;
    std::vector<Object> GetUserTransactions(const std::string& user_name) const;
    // Adds the transaction and returns its name.
    std::string AddTransaction(const Object& transaction) const;
    // Validates the transaction (e.g. the user's balance) without saving it when dry_run is true.
    std::string AddTransactionWithDryRun(const Object& transaction, bool dry_run) const;
    bool UpdateTransaction(const Object& transaction) const;
    bool DeleteTransaction(const Object& transaction) const;

    // Returns {"users": [...], "existUuids": [...]}.
    nlohmann::json GetLdapUsers(const std::string& id) const;
    // Returns {"exist": [...], "failed": [...]}.
    nlohmann::json SyncLdapUsers(const std::string& id, const nlohmann::json& users) const;
    // Fetches all the users from the LDAP server and syncs them into Casdoor.
    nlohmann::json SyncLdapUsersFromServer(const std::string& id) const;

    std::optional<Object> GetResource(const std::string& id) const;
    std::optional<Object> GetResourceEx(const std::string& owner, const std::string& name) const;
    std::vector<Object> GetResources(const std::string& owner, const std::string& user, const std::string& field,
                                     const std::string& value, const std::string& sort_field,
                                     const std::string& sort_order) const;
    std::vector<Object> GetPaginationResources(const std::string& owner, const std::string& user,
                                               const std::string& field, const std::string& value, int page_size,
                                               int page, const std::string& sort_field,
                                               const std::string& sort_order) const;
    bool AddResource(const Object& resource) const;
    bool UpdateResource(const Object& resource) const;
    // Uploads a file, returns the file URL and the name of the resource.
    std::pair<std::string, std::string> UploadResource(const std::string& user, const std::string& tag,
                                                       const std::string& parent, const std::string& full_file_path,
                                                       const std::string& file_bytes) const;
    std::pair<std::string, std::string> UploadResourceEx(const std::string& user, const std::string& tag,
                                                         const std::string& parent, const std::string& full_file_path,
                                                         const std::string& file_bytes, const std::string& created_time,
                                                         const std::string& description) const;
    bool DeleteResource(const Object& resource) const;
    // Deletes the resource, the "Direct" tag also deletes the file from the storage provider.
    bool DeleteResourceWithTag(const Object& resource, const std::string& tag) const;

    std::vector<Object> GetRecords() const;
    Page GetPaginationRecords(int p, int page_size, const QueryMap& query = {}) const;
    std::optional<Object> GetRecord(const std::string& name) const;
    bool AddRecord(Object record) const;

    void SendEmail(const std::string& title, const std::string& content, const std::string& sender,
                   const std::vector<std::string>& receivers) const;
    void SendEmailByProvider(const std::string& title, const std::string& content, const std::string& sender,
                             const std::string& provider, const std::vector<std::string>& receivers) const;
    void SendSms(const std::string& content, const std::vector<std::string>& receivers) const;
    void SendSmsByProvider(const std::string& content, const std::string& provider,
                           const std::vector<std::string>& receivers) const;
    void SendNotification(const std::string& content, const std::string& recipient) const;

    // Sets up the multi-factor authentication of the user, mfa_type is "app", "email" or "sms".
    nlohmann::json MfaInitiate(const std::string& owner, const std::string& mfa_type, const std::string& name) const;
    nlohmann::json MfaVerify(const std::string& owner, const std::string& mfa_type, const std::string& name,
                             const std::string& secret, const std::string& passcode) const;
    nlohmann::json MfaEnable(const std::string& owner, const std::string& mfa_type, const std::string& name,
                             const std::string& secret, const std::string& recovery_code) const;
    void MfaSetPreferred(const std::string& owner, const std::string& mfa_type, const std::string& name,
                         const std::string& secret = "") const;
    void MfaDelete(const std::string& owner, const std::string& name) const;

    // Calls any Casdoor API, e.g. DoGet("get-roles", {{"owner", "my-org"}}), and returns the whole
    // response {"status": "ok", "data": ..., "data2": ...}, throws Error when the status isn't "ok".
    nlohmann::json DoGet(const std::string& action, const QueryMap& query = {}) const;
    nlohmann::json DoPost(const std::string& action, const QueryMap& query, const nlohmann::json& body) const;

private:
    nlohmann::json Get(const std::string& path) const;
    nlohmann::json Post(const std::string& path, const std::string& body, const std::string& content_type) const;
    nlohmann::json PostForm(const std::string& action, const QueryMap& query, const QueryMap& form) const;
    std::vector<Object> GetList(const std::string& action, const QueryMap& query) const;
    std::optional<Object> GetOne(const std::string& action, const QueryMap& query) const;
    Page GetPage(const std::string& action, int p, int page_size, const QueryMap& query) const;
    bool Modify(const std::string& action, Object object, const std::string& default_owner,
                const std::vector<std::string>& columns = {}, const std::string& key = "name") const;
    std::pair<std::string, std::string> Upload(const QueryMap& query, const std::string& file_bytes) const;
    Token RequestToken(const std::string& form) const;
    bool ModifyUser(const std::string& action, User user) const;

    Config config_;
    std::string access_token_;  // set by WithAccessToken()
    std::string origin_;     // scheme://host[:port]
    std::string base_path_;  // path prefix of the endpoint, usually empty
};

}  // namespace casdoor

#endif  // CASDOOR_CASDOOR_H
