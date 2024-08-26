# koreader-sync-rs

Inspired by [koreader-sync-server](https://github.com/koreader/koreader-sync-server) and [kosync-dotnet](https://github.com/jberlyn/kosync-dotnet), this project aims to provide a self-hostable implementation of the KOReader sync server with Rust and Cloudflare Workers.

## Deployment

- Clone this repository: 
```
$ git clone https://github.com/MosakujiHokuto/koreader-sync-rs.git
$ cd koreader-sync-rs
```

- Create a D1 database with wrangler (https://developers.cloudflare.com/d1/get-started/):
```
$ npx wrangler d1 create prod-kosync
```
Take note of the result and update `wrangler.toml` accordingly.

- Create a secret for accessing the management API:
```
$ npx wrangler secret put MGM_TOKEN
```
The secret can be an arbitrary string, as long as it is kept secret. Anyone with the token is able to access the management API.

- (Optional) Enable registration if you want:

Change the value of `REGISTRATION` environment variable to `"enabled"`:
```
# wrangler.toml
  [vars]
- REGISTRATION="disabled"
+ REGISTRATION="enabled"
```

- Deploy the workers:
```
$ npx wrangler deploy
```

- Test the deployment status of the worker:
```
$ curl https://<domain-to-your-worker/healthcheck
{"status": "ok"}
```

## Differences from the official implementation

### Disabling registration

Inspired by [kosync-dotnet](https://github.com/jberlyn/kosync-dotnet), this implementation offers the ability to disable the registration through normal endpoint. The behaviour can be controlled by the environment variable `REGISTRATION`. If the value of this variable is anything other than "enabled", registrations through normal endpoint will be rejected.

### Password storage

As of today it is well known that you should not store plain text of the password into your database. More specifically, password-based authentication should usually be down as follows:

1. Client transport the password to server over some secured channel (e.g. TLS), so the password itself can not be eavesdropped en route.

2. Server hash the password sent by client with some secure password hashing algorithm (e.g. bcrypt, scrypt, argon2)

3. Server compare the hash result with the hashed password stored in database; if they match, the client is authenticated.

As for why the hashing of password must be done server-side, consider the purpose of saving hashed password instead of plain text:

1. Many users tend to reuse the same password on multiple platforms. If password is saved as plain-text, an attacker who obtained access to the database can easily compomise an user's accounts on every other platform.

2. If an attacker obtained access to the database, and password is saved as plain text, then the attacker can easily gain access to the services by simply login to the system using the password they obtained from database. By storing a hashed password, we force the attacker to obtain the original password from the hashed password, which is usually considered infeasible if the hash algorithm is secured.

If the hashing is done client-side, then 2. nolonger holds, since the attacker can simply craft their own client and login to the system with the hash obtained from the database directly. In other words, the "hashed password" is now essentially the same as the "plain text" of the password, since the "password" in this case is effectively just the hash obtained from user input.

However, the original implementation of the koreader-sync-server chose to let the client do the hashing with MD5. The rationale behind the decision is unclear to me, but anyways I attempt to add another level of security by essentially treating the "MD5 of the password" as the plain text of the password, and hash that again with argon2 before storing it inside database. While MD5 is not considered a secured hash nowadays, breaking it would require the attacker to either:

1. Break TLS and obtain the MD5 hash in transpotation

2. Somehow compromise into Cloudflare Workers and obtain the MD5 hash from there

3. Compromise the user device and obtain MD5 from there

4. Break argon2 and obtain the original MD5 hash from argon2 hash

1 and 4 is normally considered impossible as the timing of writing, and in case of 2 and 3, the attacker can probably just mount a much more effective attack than trying to obtain password from the MD5, so the current plan seems secure enough for me.

### Management API

This implementation includes a management API inspired by [kosync-dotnet](https://github.com/jberlyn/kosync-dotnet), however the API itself is different from those in kosync-dotnet.

All of the management API is required to be authenticated by a custom header named `x-auth-mgm-token`, the value of which should match the value of the secret variable `MGM_TOKEN`.

#### GET /manage/users

List all the users currently registered on the server.

Query params:

- `offset`: number of users to skip before the first result. **Default**: 0.
- `limit`: maximum entries returned by the request. **Default**: 50.

#### POST /manage/users

Create a user on the server. This endpoint bypasses the restriction posted by `REGISTRATION` variable.

Post body:
```json
{
   "username": "<login name of the user>",
   "password": "<MD5 hash of the password>"
}
```
