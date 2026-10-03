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

// Signs in with Casdoor from the console:
//   1. open the printed URL in a browser and sign in,
//   2. copy the `code` parameter of the URL the browser is redirected to,
//   3. paste it here to get the token and the user's claims.
//
// Configure it with the environment variables CASDOOR_ENDPOINT, CASDOOR_CLIENT_ID,
// CASDOOR_CLIENT_SECRET, CASDOOR_CERTIFICATE_FILE, CASDOOR_ORGANIZATION,
// CASDOOR_APPLICATION and CASDOOR_REDIRECT_URI.

#include <casdoor/casdoor.h>

#include <cstdlib>
#include <fstream>
#include <iostream>
#include <sstream>

static std::string Env(const char* key) {
    const char* value = std::getenv(key);
    if (value == nullptr || *value == '\0') {
        std::cerr << key << " is not set" << std::endl;
        std::exit(1);
    }
    return value;
}

int main() {
    casdoor::Config config;
    config.endpoint = Env("CASDOOR_ENDPOINT");
    config.client_id = Env("CASDOOR_CLIENT_ID");
    config.client_secret = Env("CASDOOR_CLIENT_SECRET");
    config.organization_name = Env("CASDOOR_ORGANIZATION");
    config.application_name = Env("CASDOOR_APPLICATION");

    std::ifstream cert_file(Env("CASDOOR_CERTIFICATE_FILE"));
    std::stringstream cert;
    cert << cert_file.rdbuf();
    config.certificate = cert.str();

    try {
        casdoor::Client client(config);
        std::cout << "Sign in at:\n  " << client.GetSigninUrl(Env("CASDOOR_REDIRECT_URI")) << "\n\ncode: ";

        std::string code;
        std::getline(std::cin, code);

        casdoor::Token token = client.GetOAuthToken(code);
        casdoor::Claims claims = client.ParseJwtToken(token.access_token);
        std::cout << "Signed in as " << claims.owner << "/" << claims.name << " (" << claims.display_name << ")\n"
                  << claims.payload.dump(2) << std::endl;
    } catch (const casdoor::Error& e) {
        std::cerr << "error: " << e.what() << std::endl;
        return 1;
    }
    return 0;
}
