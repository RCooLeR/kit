# Sign-in and account linking through OpenID Connect

`federation` is the browser side of OpenID Connect for an application with its own accounts. It
reads the client file, starts a sign-in or the linking of a signed-in account, and checks the
callback. `oidcsso` verifies the tokens underneath. The application keeps its accounts, the links,
its sessions, rate limits and pages.

## The client file

Each application names one private JSON file in a setting of its own, such as
`<APP>_OIDC_CONFIG_FILE`. Unknown members are refused, and a relative `client_secret_file` is read
next to the file:

```json
{"issuer": "https://login.example.com/realms/team", "client_id": "reports",
 "client_secret_file": "reports-client-secret", "required_acr": "2", "social_providers": ["google"]}
```

```go
file, err := federation.LoadFile("REPORTS_OIDC_CONFIG_FILE", path)
provider, err := oidcsso.NewLazyProvider(file.Config(publicURL)) // callback: <public URL>/api/v1/federation/callback
flow, err := federation.New(federation.Options{
    Provider: provider, Attempts: federation.NewMemoryAttempts(0), PublicURL: publicURL,
    CookieName: "reports_oidc", SocialProviders: file.SocialProviders,
})
```

`NewMemoryAttempts` suits an application that runs as one process; several replicas share an
`Attempts` implementation over their database.

## The two routes

`POST /api/v1/federation/start` (`StartPath`): after the application's own checks, call
`flow.Start` and answer the address it returns; the browser goes there.

- Sign-in: `Request{Purpose: federation.PurposeSignIn}`, optionally `Passive: true` to use an
  existing issuer session only, or `Social: "google"` for a brokered button.
- Linking: only from a signed-in session, `Request{Purpose: federation.PurposeLink, Account: id}`
  with the session's own account.

`GET /api/v1/federation/callback` (`CallbackPath`): call `flow.Finish`. On an error, show the same
failure for every case. On success:

- `Result.Interaction`: a passive check found no issuer session; show the local sign-in.
- `PurposeSignIn`: find the account linked to the exact pair `(Identity.Issuer, Identity.Subject)`.
  No link, no session. Then issue a fresh local session.
- `PurposeLink`: link the pair to `Result.Account`. Refuse a pair already linked to another
  account.

An email address never links anything. With `required_acr`, `Identity.MFAConfirmed` tells the
application that the issuer's second factor may count as its own.
