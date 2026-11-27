# OpenID Connect sign-in across applications

Point each application at the same OpenID Connect issuer. Register a separate confidential
client for each application. Give every client its own secret and register its exact callback
URL. The issuer's browser session can sign a user in to several clients. Each application owns
its account bindings, authorization checks and local sessions.

## Configure the client

Import `github.com/RCooLeR/kit/webauth/oidcsso`. Read secrets from your secret store and build
the callback from the configured public URL.

```go
provider, err := oidcsso.NewLazyProvider(oidcsso.Config{
    Issuer:       "https://login.example.com/realms/team",
    ClientID:     "reports",
    ClientSecret: secret,
    RedirectURI:  "https://reports.example.com/sign-in/return",
})
```

Handle a configuration error at startup. Discovery runs on first use, so an issuer outage
can leave local sign-in available.

## Connect the browser flow

1. Start sign-in from the browser. Generate an attempt with `oidcsso.NewAttempt` and bind it to
   that browser using a short-lived server-side record and a host-only cookie. Keep the nonce and
   PKCE verifier server-side. If you record a return destination, restrict it to a safe local path.
2. Redirect the browser to the URL from `provider.AuthorizationURL(ctx, attempt)`.
   Use `provider.PassiveAuthorizationURL(ctx, attempt)` for a top-level check of an existing
   issuer session. It sends `prompt=none`. If the provider returns `login_required` or another
   interaction error, validate the state, consume the attempt and return to the local sign-in page.
3. At the registered callback, check that the returned state matches the short-lived attempt
   bound to the current browser, consume that attempt atomically, and reject missing or repeated
   callback parameters. Pass a successful response's code to `provider.Exchange(ctx, code, attempt)`.
   Exchange verifies the signed ID token, exact issuer, single client audience and nonce.
4. Look up an explicit local binding using the exact case-sensitive pair
   `(identity.Issuer, identity.Subject)`. An unlinked identity gets no local session. Create
   links through an authenticated account flow or an administrator-controlled enrollment.
   Providers with pairwise subjects can return a different subject for each client. Use the
   subject returned for the client you are linking.
5. Apply local account and authorization policy, then issue a fresh local session with a host-only
   cookie. In production use `Secure` and `HttpOnly` cookies and choose a `SameSite` setting that
   allows the top-level callback for the attempt cookie. No app cookie or app session secret is
   shared across clients.

## Require issuer MFA

Set `Config.RequiredACR` to the exact authentication context value the configured issuer
guarantees represents MFA. Configure and document that mapping at the issuer before giving it
credit for local MFA. Kit sends `acr_values` and rejects exchanges unless the verified ID token
contains a matching `acr` string. A successful exchange under this policy sets
`Identity.MFAConfirmed`. Leave the field empty to keep enforcing MFA through your local policy.
