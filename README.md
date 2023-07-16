# casdoor-cpp-sdk

[![Discord](https://img.shields.io/discord/1022748306096537660?logo=discord&label=discord&color=5865F2)](https://discord.gg/5rPsrAzK7S)

This is Casdoor's SDK for C++, which will allow you to easily connect your application to the Casdoor authentication system without having to implement it from scratch.

Casdoor SDK is very simple to use. We will show you the steps below.

## Step1. Init SDK

Initialization requires 5 parameters, which are all string type:

| Name (in order) | Must | Description                                         |
| --------------- | ---- | --------------------------------------------------- |
| endpoint        | Yes  | Casdoor Server Url, such as `http://localhost:8000` |
| client_id        | Yes  | Client ID for the Casdoor application               |
| client_secret    | Yes  | Client secret for the Casdoor application           |
| certificate     | Yes  | x509 certificate content of Application.cert        |
| org_name         | Yes  | The name for the Casdoor organization               |
<!-- | appName         | No   | The name for the Casdoor application                | -->

```cpp
CasdoorConfig casdoorConfig = new CasdoorConfig(endpoint, client_id, client_secret, certificate, org_name);

```

## Step2. Get token and parse

After Casdoor verification passed, it will be redirected to your application with code and state, like https://forum.casbin.com/callback?code=xxx&state=yyyy.

Your web application can get the `cod`e and call `GetOAuthToken(code=code)`, then parse out jwt token.

```cpp
string access_token = casdoorConfig.GetOAuthToken(code)
strin user_json = casdoorConfig.ParseJwtToken(access_token)
```
`user_json` is the JSON data decoded from the access_token, which contains user info and other useful stuff.

## Step3. Interact with the users

In casdoor-cpp-sdk, `CasdoorConfig`  support basic user operations, like:
* `GetUsers()` : Get all users.
* `GetUser(string user_id)`: get single user by user name.
* `ModifyUser(string method, CasdoorUser user)/AddUser(string method, CasdoorUser user)/UpdateUser(string method, CasdoorUser user)/DeleteUser(string method, CasdoorUser user)` : modify user entry in database.
