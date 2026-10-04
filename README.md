# Casdoor C++ SDK

<p align="center">
  <a href="#badge">
    <img alt="semantic-release" src="https://img.shields.io/badge/%20%20%F0%9F%93%A6%F0%9F%9A%80-semantic--release-e10079.svg">
  </a>
  <a href="https://github.com/casdoor/casdoor-cpp-sdk/actions/workflows/ci.yml">
    <img alt="CI" src="https://github.com/casdoor/casdoor-cpp-sdk/actions/workflows/ci.yml/badge.svg">
  </a>
  <a href="https://github.com/casdoor/casdoor-cpp-sdk/releases/latest">
    <img alt="GitHub Release" src="https://img.shields.io/github/v/release/casdoor/casdoor-cpp-sdk.svg">
  </a>
  <a href="https://en.cppreference.com/w/cpp/17">
    <img alt="C++17" src="https://img.shields.io/badge/C%2B%2B-17-00599C?logo=cplusplus">
  </a>
  <a href="https://cmake.org">
    <img alt="CMake" src="https://img.shields.io/badge/CMake-3.16%2B-064F8C?logo=cmake">
  </a>
</p>

<p align="center">
  <a href="https://github.com/casdoor/casdoor-cpp-sdk/blob/master/LICENSE">
    <img src="https://img.shields.io/github/license/casdoor/casdoor-cpp-sdk?style=flat-square" alt="license">
  </a>
  <a href="https://github.com/casdoor/casdoor-cpp-sdk/issues">
    <img alt="GitHub issues" src="https://img.shields.io/github/issues/casdoor/casdoor-cpp-sdk?style=flat-square">
  </a>
  <a href="#">
    <img alt="GitHub stars" src="https://img.shields.io/github/stars/casdoor/casdoor-cpp-sdk?style=flat-square">
  </a>
  <a href="https://github.com/casdoor/casdoor-cpp-sdk/network">
    <img alt="GitHub forks" src="https://img.shields.io/github/forks/casdoor/casdoor-cpp-sdk?style=flat-square">
  </a>
  <a href="https://discord.gg/5rPsrAzK7S">
    <img alt="Casdoor" src="https://img.shields.io/discord/1022748306096537660?style=flat-square&logo=discord&label=discord&color=5865F2">
  </a>
</p>

Casdoor C++ SDK is the official C++ client library for [Casdoor](https://casdoor.ai/). It lets your C++ application sign users in with Casdoor (OAuth 2.0 / OIDC), verify the JWT tokens issued by Casdoor, and manage users, organizations, applications, roles, permissions and all the other Casdoor objects through the Casdoor APIs.

The SDK has the same features as [casdoor-go-sdk](https://github.com/casdoor/casdoor-go-sdk).

Example apps: [casdoor-cpp-qt-example](https://github.com/casdoor/casdoor-cpp-qt-example) (Qt desktop app) and [examples/console](examples/console/main.cpp).

## 📋 Table of Contents

- [Features](#-features)
- [Requirements](#-requirements)
- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [Configuration](#️-configuration)
- [Authentication](#-authentication)
- [Resource Management](#-resource-management)
- [API Reference](#-api-reference)
- [Development](#-development)
- [License](#-license)

## ✨ Features

- **OAuth 2.0 Authentication**: authorization code, password and refresh token grants, token introspection, SSO logout
- **JWT Verification**: verify the tokens signed by Casdoor (RS256/384/512, PS256/384/512, ES256/384/512)
- **Calling APIs as the User**: `WithAccessToken()` calls the APIs with the user's own permissions
- **User Management**: CRUD, lookup by email / phone / user ID, pagination, password check and change
- **Organization & Application Management**: organizations, applications, groups, certificates, providers, LDAP
- **Authorization**: roles, permissions, models, adapters, enforcers, policies, `Enforce()` and `BatchEnforce()`
- **Billing**: products, orders, payments, plans, pricings, subscriptions and transactions
- **Messaging**: send emails, SMS and notifications
- **Multi-Factor Authentication (MFA)**: TOTP, email and SMS MFA setup
- **Other Objects**: sessions, tokens, webhooks, syncers, invitations, resources (file upload) and records

## 🧰 Requirements

- A C++17 compiler (GCC 8+, Clang 7+, MSVC 2019+)
- CMake 3.16+
- OpenSSL 1.1.1 or 3.x (`libssl-dev` on Debian/Ubuntu, `openssl` on Homebrew, `openssl` on vcpkg)

The other dependencies are header-only and bundled in [third_party](third_party): [cpp-httplib](https://github.com/yhirose/cpp-httplib) 0.59.0, [jwt-cpp](https://github.com/Thalhammer/jwt-cpp) 0.7.2 and [nlohmann/json](https://github.com/nlohmann/json) 3.12.0. If your project already has a `nlohmann_json::nlohmann_json` target, the SDK uses it instead of the bundled copy.

## 📦 Installation

With CMake's `FetchContent`:

```cmake
include(FetchContent)
FetchContent_Declare(casdoor
    GIT_REPOSITORY https://github.com/casdoor/casdoor-cpp-sdk.git
    GIT_TAG master)  # or a release tag
FetchContent_MakeAvailable(casdoor)

target_link_libraries(your_app PRIVATE casdoor::casdoor)
```

Or copy this repository into your project and use `add_subdirectory(casdoor-cpp-sdk)`.

## 🚀 Quick Start

```cpp
#include <casdoor/casdoor.h>

casdoor::Config config;
config.endpoint = "http://localhost:8000";
config.client_id = "<client ID>";
config.client_secret = "<client secret>";
config.certificate = "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----";
config.organization_name = "my-organization";
config.application_name = "my-application";

casdoor::Client client(config);

std::vector<casdoor::User> users = client.GetUsers();
std::cout << "Found " << users.size() << " users" << std::endl;
```

## ⚙️ Configuration

### Configuration Parameters

| Field             | Required | Description                                                                 |
|-------------------|----------|-----------------------------------------------------------------------------|
| endpoint          | Yes      | Casdoor server URL, such as `http://localhost:8000`, http and https work    |
| client_id         | Yes      | Client ID of the Casdoor application                                        |
| client_secret     | Yes      | Client secret of the Casdoor application                                    |
| certificate       | Yes      | x509 certificate (PEM) of the application's cert, used to verify JWT tokens |
| organization_name | Yes      | Name of the Casdoor organization                                            |
| application_name  | Yes      | Name of the Casdoor application                                             |
| timeout_seconds   | No       | Timeout of every HTTP request, defaults to 10 seconds                       |
| custom_headers    | No       | HTTP headers added to all the API requests, e.g. `{{"Accept-Language", "de"}}` |

All the values are on the application's edit page in Casdoor. The certificate is the public certificate of the cert the application uses (Certs page → the cert → "Certificate").

### Objects

`casdoor::User` has members for the common fields. All other fields returned by Casdoor are kept in `User::extra` and sent back unchanged by `UpdateUser()`, so updating a user never clears fields the SDK doesn't know about.

The other objects (roles, groups, products, ...) are `casdoor::Object`, an alias of `nlohmann::json`, with the same fields as Casdoor's JSON and the structs of casdoor-go-sdk:

```cpp
casdoor::Object role = {{"name", "admin"}, {"displayName", "Administrator"}, {"users", {"my-organization/alice"}}};
client.AddRole(role);
```

### Errors

Every method that talks to Casdoor throws `casdoor::Error` on network errors, HTTP errors, Casdoor API errors (`"status": "error"`) and OAuth errors (`invalid_grant`, ...). `Error::http_status()` returns the HTTP status when there is one. `Get*(name)` returns `std::nullopt` when the object doesn't exist, the modifying methods return `true` when Casdoor changed something.

## 🔐 Authentication

### OAuth 2.0 Flow

Send the user to the sign-in page. After signing in, Casdoor redirects to `redirect_uri` with `code` and `state` parameters. The redirect URI must be in the application's "Redirect URLs".

```cpp
std::string state = /* a random string, kept until the callback */;
std::string url = client.GetSigninUrl("http://localhost:8080/callback", state);
```

In the callback, check `state`, then exchange the code for tokens and verify the access token:

```cpp
try {
    casdoor::Token token = client.GetOAuthToken(code);
    casdoor::Claims claims = client.ParseJwtToken(token.access_token);

    std::cout << claims.owner << "/" << claims.name << " " << claims.email << std::endl;
    std::cout << claims.payload["signupApplication"] << std::endl;  // any other claim
} catch (const casdoor::Error& e) {
    std::cerr << e.what() << std::endl;
}
```

`ParseJwtToken()` checks the signature against `config.certificate`, the expiry, and that the token was issued for `config.client_id`. It throws `casdoor::Error` if any check fails, so never use a token's claims without it.

`GetSignupUrl(enable_password, redirect_uri)`, `GetUserProfileUrl(user_name, access_token)` and `GetMyProfileUrl(access_token)` build the URLs of the other Casdoor pages.

### Password Grant, Impersonation, Refresh and Introspection

```cpp
// needs the "password" grant type in the application
casdoor::Token token = client.GetOAuthTokenByPassword("alice", "password");

// signs in as any user of the organization with the organization's master password
casdoor::Token token2 = client.ImpersonateUser("alice", "<master password>");

casdoor::Token refreshed = client.RefreshOAuthToken(token.refresh_token);

nlohmann::json result = client.IntrospectToken(token.access_token);
bool active = result.value("active", false);
```

### Calling APIs With the User's Access Token

By default, the SDK calls the Casdoor APIs as the application itself: it authenticates with the client ID and client secret, so the calls have the application's (admin) permissions.

To call the APIs on behalf of the signed-in user instead, use `WithAccessToken()` with the user's access token. It returns a new client that sends the `Authorization: Bearer <access_token>` header, so Casdoor treats the requests as being made by that user and the user's own permissions apply:

```cpp
casdoor::Client user_client = client.WithAccessToken(token.access_token);

// "Who am I"
std::optional<casdoor::User> account = user_client.GetAccount();

// Any other API can be called in the same way
std::vector<casdoor::User> users = user_client.GetUsers();
```

The original client is not changed, so it's safe to create one such client per incoming request.

**Note**: a non-admin user can only access their own data. If an API throws a permission error, the user simply isn't allowed to call it — use the application's client (without `WithAccessToken()`) for admin operations.

### Logout

```cpp
client.Logout(access_token);                // signs the user out of all the applications and devices (SSO logout)
client.LogoutCurrentSession(access_token);  // only signs out the session of this access token
```

## 📦 Resource Management

### Object Owner

Every object in Casdoor is identified by an ID of the form `owner/name`, where the owner is an organization (`role`, `group`, `user`, `product`, `ldap`, ...) or the built-in `admin` owner (`organization`, `application`, `token`).

The SDK fills in the owner for you when the object has none: `config.organization_name`, or `admin` for the object types listed above. You can address an object in another organization by passing a qualified `owner/name` ID instead of a plain name, and by setting the `owner` field explicitly when creating or updating an object:

```cpp
client.GetRole("my-role");            // "my-organization/my-role"
client.GetRole("other-org/my-role");  // "other-org/my-role"
client.AddRole({{"owner", "other-org"}, {"name", "my-role"}});  // created in "other-org"
```

### Method Patterns

Each object type has the same methods, e.g. for roles:

- `GetRoles()` - get all the objects of the organization
- `GetPaginationRoles(p, page_size, query)` - get a page of the objects, returns a `Page` with `items` and `total`. `query` can filter and sort, e.g. `{{"field", "name"}, {"value", "abc"}, {"sortField", "createdTime"}, {"sortOrder", "descend"}}`
- `GetRole(name)` - get an object by name (or `owner/name` ID)
- `AddRole(object)` - create an object
- `UpdateRole(object)` - update an object
- `UpdateRoleForColumns(object, columns)` - only update the given columns
- `DeleteRole(object)` - delete an object

The object types: `Adapter`, `Application`, `Cert`, `Enforcer`, `Group`, `Invitation`, `Ldap`, `Model`, `Order`, `Organization`, `Payment`, `Permission`, `Plan`, `Pricing`, `Product`, `Provider`, `Role`, `Subscription`, `Syncer`, `Token` and `Webhook`. Users (`casdoor::User`), sessions, transactions, resources and records have their own methods, see below.

### Users

```cpp
client.GetUsers();
client.GetPaginationUsers(1, 10);
client.GetUser("alice");
client.GetUserByEmail("alice@example.com");
client.GetUserByPhone("2025550123");
client.GetUserByUserId("<user id>");
client.GetSortedUsers("created_time", 10);
client.GetGlobalUsers();   // users of all organizations
client.GetUserCount("1");  // "1" for online users, "0" for offline users, "" for all users

client.AddUser(user);
client.UpdateUser(user);
client.UpdateUserForColumns(user, {"displayName", "email"});
client.UpdateUserById("my-organization/alice", user);
client.UpdateUserByUserId("my-organization", "<user id>", user);
client.DeleteUser(user);

client.CheckUserPassword(user);  // true if user.password is the user's password
client.SetPassword("my-organization", "alice", "old-password", "new-password");
```

### Permissions, Enforcers and Policies

```cpp
// Check a request against a permission (or a model / resource / enforcer / owner)
bool allowed = client.Enforce("my-organization/read-data", "", "", "", "", {"my-organization/alice", "data1", "read"});
auto results = client.BatchEnforce("my-organization/read-data", "", "", "", "",
                                   {{"my-organization/alice", "data1", "read"}, {"my-organization/bob", "data1", "read"}});

casdoor::Object enforcer = *client.GetEnforcer("my-enforcer");
client.GetPolicies("my-enforcer");
client.GetFilteredPolicies("my-organization/my-enforcer", {{{"ptype", "p"}, {"fieldIndex", 0}, {"fieldValues", {"alice"}}}});
client.AddPolicy(enforcer, {{"Ptype", "p"}, {"V0", "alice"}, {"V1", "data1"}, {"V2", "read"}});
client.UpdatePolicy(enforcer, old_policy, new_policy);
client.RemovePolicy(enforcer, policy);
```

### Billing: Products, Orders, Payments and Transactions

```cpp
// Place an order of products for a user and pay it with a payment provider
casdoor::Object order = client.PlaceOrder({{{"name", "my-product"}, {"quantity", 1}}}, "alice");
casdoor::Object payment = client.PayOrder(order["name"], "my-payment-provider");
client.CancelOrder(order["name"]);

client.GetUserOrders("alice");
client.GetUserPayments("alice");
client.GetUserTransactions("alice");

client.AddTransactionWithDryRun(transaction, true);        // validates (e.g. the balance) without saving it
std::string name = client.AddTransaction(transaction);    // returns the name of the transaction
```

### Email, SMS and Notifications

```cpp
client.SendEmail("Hello", "Hello world", "Casdoor", {"alice@example.com"});
client.SendEmailByProvider("Hello", "Hello world", "Casdoor", "my-email-provider", {"alice@example.com"});
client.SendSms("123456", {"+12025550123"});
client.SendSmsByProvider("123456", "my-sms-provider", {"+12025550123"});
client.SendNotification("Hello", "alice");
```

### Resources (File Upload)

```cpp
auto [file_url, name] = client.UploadResource("alice", "avatar", "user", "/avatar/alice.png", file_bytes);
client.GetResources("my-organization", "alice", "", "", "", "");
client.DeleteResourceWithTag(resource, "Direct");
```

### Multi-Factor Authentication

```cpp
nlohmann::json setup = client.MfaInitiate("my-organization", "app", "alice");
client.MfaVerify("my-organization", "app", "alice", setup["secret"], "<passcode>");
client.MfaEnable("my-organization", "app", "alice", setup["secret"], "<recovery code>");
client.MfaSetPreferred("my-organization", "app", "alice");
client.MfaDelete("my-organization", "alice");
```

### Other APIs

`DoGet(action, query)` and `DoPost(action, query, body)` call any other Casdoor API and return the whole JSON response.

## 📚 API Reference

| Object           | Methods                                                                                                                      |
|------------------|------------------------------------------------------------------------------------------------------------------------------|
| **Auth**         | `GetOAuthToken`, `GetOAuthTokenByPassword`, `ImpersonateUser`, `RefreshOAuthToken`, `IntrospectToken`, `ParseJwtToken`, `Logout`, `LogoutCurrentSession`, `WithAccessToken`, `GetAccount` |
| **URL**          | `GetSigninUrl`, `GetSignupUrl`, `GetUserProfileUrl`, `GetMyProfileUrl`                                                       |
| **User**         | CRUD + pagination, `GetUserByEmail`, `GetUserByPhone`, `GetUserByUserId`, `GetSortedUsers`, `GetGlobalUsers`, `GetUserCount`, `UpdateUserForColumns`, `UpdateUserById`, `UpdateUserByUserId`, `CheckUserPassword`, `SetPassword` |
| **Object types** | CRUD + pagination + `Update*ForColumns`, see [Method Patterns](#method-patterns)                                            |
| **Organization / Application / Cert / Permission** | `GetOrganizationNames`, `GetOrganizationApplications`, `GetGlobalCerts`, `GetPermissionsByRole`            |
| **Policy**       | `GetPolicies`, `GetFilteredPolicies`, `AddPolicy`, `UpdatePolicy`, `RemovePolicy`                                            |
| **Enforce**      | `Enforce`, `BatchEnforce`                                                                                                    |
| **Session**      | CRUD + pagination, `GetSession(name, application)`, `UpdateSessionForColumns`                                                |
| **Order**        | `GetUserOrders`, `PlaceOrder`, `PayOrder`, `BuyProduct`, `CancelOrder`                                                       |
| **Payment**      | `GetUserPayments`, `NotifyPayment`, `InvoicePayment`                                                                         |
| **Transaction**  | CRUD + pagination, `GetUserTransactions`, `AddTransactionWithDryRun`                                                         |
| **Invitation**   | `GetInvitationInfo`                                                                                                          |
| **LDAP**         | `GetLdapUsers`, `SyncLdapUsers`, `SyncLdapUsersFromServer`                                                                   |
| **Resource**     | `GetResources`, `GetPaginationResources`, `GetResource`, `GetResourceEx`, `AddResource`, `UpdateResource`, `UploadResource`, `UploadResourceEx`, `DeleteResource`, `DeleteResourceWithTag` |
| **Record**       | `GetRecords`, `GetPaginationRecords`, `GetRecord`, `AddRecord`                                                               |
| **Email / SMS / Notification** | `SendEmail`, `SendEmailByProvider`, `SendSms`, `SendSmsByProvider`, `SendNotification`                         |
| **MFA**          | `MfaInitiate`, `MfaVerify`, `MfaEnable`, `MfaSetPreferred`, `MfaDelete`                                                      |
| **Low-level**    | `DoGet`, `DoPost`, `GetId`                                                                                                   |

## 🛠 Development

```bash
cmake -S . -B build
cmake --build build
ctest --test-dir build --output-on-failure
```

The tests sign tokens with the keys in [tests/data](tests/data) and run offline. To also run them against a Casdoor server, start one with the data in [.ci/casdoor/init_data.json](.ci/casdoor/init_data.json), save the public certificate of its `cert-built-in` to `tests/data/casdoor.crt` and set `CASDOOR_TEST_ENDPOINT`. [.github/workflows/ci.yml](.github/workflows/ci.yml) does exactly that:

```bash
docker run -d --name casdoor -p 8000:8000 \
  -e driverName=sqlite \
  -e dataSourceName='file:casdoor.db?cache=shared' \
  -e initDataFile=/init_data.json \
  -v "$PWD/.ci/casdoor/init_data.json:/init_data.json:ro" \
  casbin/casdoor-all-in-one
```

Releases are tagged automatically by semantic-release when commits are pushed to `master`.

## 📄 License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.
