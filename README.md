# casdoor-cpp-sdk

[![CI](https://github.com/casdoor/casdoor-cpp-sdk/actions/workflows/ci.yml/badge.svg)](https://github.com/casdoor/casdoor-cpp-sdk/actions/workflows/ci.yml)
[![C++17](https://img.shields.io/badge/C%2B%2B-17-00599C?logo=cplusplus)](https://en.cppreference.com/w/cpp/17)
[![CMake](https://img.shields.io/badge/CMake-3.16%2B-064F8C?logo=cmake)](https://cmake.org)
[![License](https://img.shields.io/github/license/casdoor/casdoor-cpp-sdk)](https://github.com/casdoor/casdoor-cpp-sdk/blob/master/LICENSE)
[![GitHub last commit](https://img.shields.io/github/last-commit/casdoor/casdoor-cpp-sdk)](https://github.com/casdoor/casdoor-cpp-sdk/commits/master)
[![GitHub issues](https://img.shields.io/github/issues/casdoor/casdoor-cpp-sdk)](https://github.com/casdoor/casdoor-cpp-sdk/issues)
[![Discord](https://img.shields.io/discord/1022748306096537660?logo=discord&label=discord&color=5865F2)](https://discord.gg/5rPsrAzK7S)

Casdoor's SDK for C++. It signs users in with [Casdoor](https://casdoor.org) (OAuth 2.0 authorization code flow), verifies the tokens Casdoor issues, and manages users through the Casdoor API.

Example apps: [casdoor-cpp-qt-example](https://github.com/casdoor/casdoor-cpp-qt-example) (Qt desktop app) and [examples/console](examples/console/main.cpp).

## Requirements

- A C++17 compiler (GCC 8+, Clang 7+, MSVC 2019+)
- CMake 3.16+
- OpenSSL 1.1.1 or 3.x (`libssl-dev` on Debian/Ubuntu, `openssl` on Homebrew, `openssl` on vcpkg)

The other dependencies are header-only and bundled in [third_party](third_party): [cpp-httplib](https://github.com/yhirose/cpp-httplib) 0.59.0, [jwt-cpp](https://github.com/Thalhammer/jwt-cpp) 0.7.2 and [nlohmann/json](https://github.com/nlohmann/json) 3.12.0. If your project already has a `nlohmann_json::nlohmann_json` target, the SDK uses it instead of the bundled copy.

## Installation

With CMake's `FetchContent`:

```cmake
include(FetchContent)
FetchContent_Declare(casdoor
    GIT_REPOSITORY https://github.com/casdoor/casdoor-cpp-sdk.git
    GIT_TAG master)
FetchContent_MakeAvailable(casdoor)

target_link_libraries(your_app PRIVATE casdoor::casdoor)
```

Or copy this repository into your project and use `add_subdirectory(casdoor-cpp-sdk)`.

## Usage

### 1. Create a client

All values are on the application's edit page in Casdoor. The certificate is the public certificate of the cert the application uses (Certs page).

```cpp
#include <casdoor/casdoor.h>

casdoor::Config config;
config.endpoint = "https://door.casdoor.com";
config.client_id = "<client ID>";
config.client_secret = "<client secret>";
config.certificate = "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----";
config.organization_name = "<organization>";
config.application_name = "<application>";

casdoor::Client client(config);
```

### 2. Sign the user in

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

`ParseJwtToken` checks the signature against `config.certificate` (RS256/384/512, PS256/384/512, ES256/384/512), the expiry, and that the token was issued for `config.client_id`. It throws `casdoor::Error` if any check fails, so never use a token's claims without it.

Other token methods: `RefreshOAuthToken(refresh_token)` and `GetOAuthTokenByPassword(username, password)` (needs the "password" grant type in the application).

### 3. Manage users

These calls authenticate with the client ID and secret and work on `config.organization_name`.

```cpp
std::vector<casdoor::User> users = client.GetUsers();

std::optional<casdoor::User> alice = client.GetUser("alice");
if (alice) {
    alice->display_name = "Alice";
    client.UpdateUser(*alice);
}

casdoor::User bob;
bob.name = "bob";
bob.password = "a-strong-password";
bob.email = "bob@example.com";
client.AddUser(bob);
client.DeleteUser(bob);
```

`User` has members for the common fields. All other fields returned by Casdoor are kept in `User::extra` and sent back unchanged by `UpdateUser`, so updating a user never clears fields the SDK doesn't know about.

### URLs

- `GetSigninUrl(redirect_uri, state)`
- `GetSignupUrl(enable_password, redirect_uri)`
- `GetUserProfileUrl(user_name, access_token)`
- `GetMyProfileUrl(access_token)`

### Errors

Every method that talks to Casdoor throws `casdoor::Error` on network errors, HTTP errors, Casdoor API errors (`"status": "error"`) and OAuth errors (`invalid_grant`, ...). `Error::http_status()` returns the HTTP status when there is one.

## Development

```bash
cmake -S . -B build
cmake --build build
ctest --test-dir build --output-on-failure
```

The tests sign tokens with the keys in [tests/data](tests/data) and run offline. To also run them against a Casdoor server, start one with the data in [.ci/casdoor/init_data.json](.ci/casdoor/init_data.json), save the public certificate of its `cert-built-in` to `tests/data/casdoor.crt` and set `CASDOOR_TEST_ENDPOINT`. [.github/workflows/ci.yml](.github/workflows/ci.yml) does exactly that.

## License

Apache-2.0
