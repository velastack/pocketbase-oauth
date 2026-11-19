# pocketbase-oauth

Turns [PocketBase](https://pocketbase.io) into an OAuth 2.1 authorization server, so other applications can act for the users of an auth collection with a scoped, revocable token instead of the user's own.

It implements what the [Model Context Protocol](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization) asks of an authorization server, which is what lets ChatGPT, Claude and other MCP clients sign in to an app built on PocketBase:

- authorization code grant with PKCE (S256 only), for public and confidential clients
- refresh token rotation with reuse detection
- resource indicators ([RFC 8707](https://www.rfc-editor.org/rfc/rfc8707.html)): a token is bound to the resource it was asked for
- server metadata ([RFC 8414](https://datatracker.ietf.org/doc/html/rfc8414)) and the `iss` response parameter ([RFC 9207](https://datatracker.ietf.org/doc/html/rfc9207))
- [Client ID Metadata Documents](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-00) and dynamic client registration ([RFC 7591](https://datatracker.ietf.org/doc/html/rfc7591))
- revocation ([RFC 7009](https://datatracker.ietf.org/doc/html/rfc7009)) and introspection ([RFC 7662](https://datatracker.ietf.org/doc/html/rfc7662))

The plugin uses only public PocketBase APIs and has no dependency besides PocketBase, so it works with vanilla PocketBase as well as [velabase](https://github.com/velastack/velabase), which has it built in.

## Install

```go
import "github.com/velastack/pocketbase-oauth"

oauth.MustRegister(app, oauth.Config{})
```

| Option | Default | |
|---|---|---|
| `Issuer` | the Application URL setting | The public origin clients reach the server on. |
| `AuthorizePath` | `/oauth/authorize` | Where, under the issuer, your app serves the sign-in and consent page. |
| `AccessTokenTTL` | 1 hour | |
| `RefreshTokenTTL` | 30 days | Each use issues a new one, so a client in use does not expire. |
| `CodeTTL` | 5 minutes | |
| `DisableDynamicRegistration` | `false` | Leaves Client ID Metadata Documents as the only way in for a new client. |
| `HTTPClient` | public addresses only | Fetches Client ID Metadata Documents. |

## How it fits together

PocketBase has no browser session: your app holds the user's auth token. So the page a person sees, the **authorization endpoint**, is yours, and the plugin does everything else.

```
client ──▶ your app  /oauth/authorize?client_id=…&code_challenge=…      (browser)
              │  sign the person in, however your app does
              │  GET  /api/oauth/consent?<the same query>     who is asking, for what
              │  POST /api/oauth/consent  (as the user)       their yes or no
              ◀─ {redirectTo}  ──▶ back to the client with ?code=…&iss=…
client ──▶ POST /api/oauth/token                               code → tokens
client ──▶ your API, with  Authorization: Bearer oat_…
              │  POST /api/oauth/introspect  (as a superuser)  who and what is this token
```

### The consent page

`GET /api/oauth/consent` takes the query the authorization endpoint was opened with and needs no auth. It answers:

```json
{
  "client": { "id": "…", "name": "Example Client", "uri": "https://…", "logoUri": "https://…", "verified": false },
  "redirectUri": "https://client.example.com/callback",
  "redirectHost": "client.example.com",
  "scope": "content:read content:write",
  "resource": "https://app.example.com/mcp"
}
```

A client names itself, so show `redirectHost` next to the name: it is the one thing on the page the client cannot make up.

If the request is invalid the answer is a `400` with `error` and `error_description`. Without `redirectTo`, the client or its redirect URI could not be trusted: show the error and send the person nowhere. With `redirectTo`, the client can be told what was wrong by sending the browser there, but think before doing that unasked: registration is open, so anyone can make a link to your consent page that would bounce a visitor to an address of their choosing. Showing the error on the page is the safe default.

Two more things are the page's to check, because only your app knows them:

- **`resource`.** A token is good at the server it names. Approve a request only when `resource` is one your app serves; otherwise someone else's server could send your users here and leave with tokens made out to it.
- **Framing.** Send `Content-Security-Policy: frame-ancestors 'none'` with the page, so another site cannot put it in a frame and steer a click.

`POST /api/oauth/consent`, with the user's PocketBase token, takes the same parameters as JSON plus the decision:

```js
const { redirectTo } = await pb.send("/api/oauth/consent", {
    method: "POST",
    body: {
        ...Object.fromEntries(url.searchParams), // client_id, redirect_uri, code_challenge, …
        approve: true,                           // false sends back access_denied
        granted_scope: "content:read",           // optional: less (or, with no scope asked, other) than requested
    },
});
location.href = redirectTo;
```

Superusers cannot approve a client. Posting to this endpoint from your server, in a form action protected against cross-site requests, is what keeps another site from approving on the person's behalf.

### Scopes

The plugin does not define scopes. It checks their syntax, stores what the consent page granted, and reports it on introspection; what a scope means and which ones exist is up to the resource server. Advertise them in the resource server's own metadata (`scopes_supported` of [RFC 9728](https://datatracker.ietf.org/doc/html/rfc9728)).

### Checking a token

An access token is not a PocketBase auth token and does not open the regular API: API rules know nothing about scopes. The resource server asks what it stands for, as a superuser:

```js
const info = await superuserClient.send("/api/oauth/introspect", { method: "POST", body: { token } });
// { active: true, sub: "<record id>", collection_name: "users", scope: "content:read",
//   aud: "https://app.example.com/mcp", client_id: "…", grant_id: "…", exp: 1790000000 }
```

Check `active`, then that `aud` is your own resource URL (a token issued for another server must be refused), then the scope the operation needs.

### What a user approved

```
GET    /api/oauth/grants        the signed-in user's approved clients
DELETE /api/oauth/grants/{id}   revoke one, with all its tokens
```

## Clients

A client is one of:

- **A Client ID Metadata Document.** The `client_id` is an `https` URL of a JSON document with `client_id` (the same URL), `client_name` and `redirect_uris`. It is fetched on first use, and again when its cache headers say so (between 5 minutes and a day). Only public clients (`token_endpoint_auth_method: "none"`) are supported this way. The fetch only connects to public addresses, does not follow redirects, and refuses documents over 16 kB.
- **Dynamically registered.** `POST /api/oauth/register` with RFC 7591 metadata returns a `client_id`, and a `client_secret` when `token_endpoint_auth_method` is `client_secret_post` or `client_secret_basic`. Registration is open, as the protocol intends, rate limited per address, and clients nobody approved are removed after 30 days.

Redirect URIs must be `https`, `http` on a loopback address (where any port then matches), or a native app's own scheme. They are matched exactly.

## Tokens

Codes, access and refresh tokens are random strings, stored only as SHA-256 hashes in the `_oauthTokens` system collection. An authorization code and a refresh token each work once. Presenting a used one again revokes the grant and everything issued under it, except that a refresh retried within a minute is only refused, so a client that lost the answer to a refresh is not signed out.

Approving a client again for the same resource replaces what it had. Deleting a user deletes their grants.

## Data

Three system collections, readable by superusers: `_oauthClients`, `_oauthGrants` and `_oauthTokens`. Expired rows are removed hourly.

## Development

```sh
go vet ./...
go test -race ./...
go run ./examples/base serve
```
