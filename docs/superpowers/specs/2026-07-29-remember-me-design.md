# Remember Me — Design

Date: 2026-07-29
Status: Approved
Scope: `BasicAuthGuard` library (`AspNetCore.BasicAuthentication`)

## Problem

Browsers prompt for Basic credentials with a native dialog and cache them only for
the browser session. After a restart, the user is prompted again. Users want a
"remember me" experience.

The native dialog is browser chrome. A server cannot add a checkbox to it — the only
thing the server controls is the `WWW-Authenticate: Basic realm=...` challenge.

## Solution

After a successful Basic authentication, the library issues a persistent, encrypted
cookie. On later requests that carry no `Authorization` header, the cookie
authenticates the user, so the native dialog does not reappear until the cookie
expires or is cleared.

Opt-in is config-driven: the app enables `RememberMe`; every successful Basic
authentication then receives the cookie. There is no per-request or per-user opt-in
in this version.

## Public API

### `Options/RememberMeOptions.cs` (new)

```csharp
public class RememberMeOptions
{
    public string CookieName { get; set; } = ".BasicAuthGuard.Remember";
    public TimeSpan Duration { get; set; } = TimeSpan.FromDays(14);
    public bool SlidingExpiration { get; set; } = false;
    public CookieSecurePolicy SecurePolicy { get; set; } = CookieSecurePolicy.Always;
    public SameSiteMode SameSite { get; set; } = SameSiteMode.Lax;
    public string Path { get; set; } = "/";
    public string? Domain { get; set; }
}
```

`HttpOnly` is always `true` and is not configurable.

Validation at configure time: `Duration` must be greater than `TimeSpan.Zero` and at
most 365 days; otherwise `ArgumentOutOfRangeException`.

### `BasicAuthenticationOptions` (edited)

- `public RememberMeOptions? RememberMe { get; set; }` — `null` means the feature is off.
- `public BasicAuthenticationOptions WithRememberMe(Action<RememberMeOptions> configure)`
  — matches the existing `WithRateLimiting` / `WithIpWhitelist` / `WithAuditLog` style.

### `Services/RememberMeTicketProtector.cs` (new)

```csharp
public interface IRememberMeTicketProtector
{
    string Protect(AuthenticationTicket ticket, TimeSpan lifetime);
    AuthenticationTicket? Unprotect(string value);
}
```

- Wraps `IDataProtectionProvider` and uses `ITimeLimitedDataProtector`.
- Payload is serialized with `TicketSerializer.Default`, then protected, then encoded
  base64url for the cookie value.
- Data Protection purpose string: `"BasicAuthGuard.RememberMe.v1"`.
- `Unprotect` returns `null` on tampering, expiry, wrong purpose, or malformed input —
  it never throws to the caller.
- Server-side expiry is enforced by the time-limited protector, so editing the cookie's
  browser-side lifetime does not extend it.
- Registered in `ServiceCollectionExtensions`. The handler takes it as an optional
  constructor parameter, the same pattern already used for `IRateLimiter` and
  `IAuditLogger`.

No new NuGet package is required — the project already has
`<FrameworkReference Include="Microsoft.AspNetCore.App" />`, which supplies both Data
Protection and `TicketSerializer`.

## Request flow

Changes are confined to `BasicAuthenticationHandler`. `UrlBasicAuthenticationMiddleware`
is unchanged and stays header-only.

1. `AllowAnonymous` and IP whitelist / blacklist checks run first, unchanged. The
   IP-bypass path issues no cookie.
2. If there is no `Authorization` header and `RememberMe` is enabled, try the cookie:
   - `Unprotect` fails (tampered, expired, malformed) → delete the cookie and return
     `NoResult()`, which produces the normal 401 challenge.
   - Success → revalidate (below). If revalidation passes, return `Success`. If
     `SlidingExpiration` is `true`, re-issue the cookie with a fresh lifetime.
3. If an `Authorization` header is present, it always wins over the cookie. This lets a
   user switch identity or re-authenticate after a password change.
4. After a successful header authentication, append the cookie.
5. The rate limiter is not consulted on the cookie path — no password guessing is
   possible there. It behaves exactly as today on the header path.

### Revalidation

Given the username and claims recovered from the ticket:

- `Options.Users` is populated → re-look up the user by username. Reject if the user is
  missing, `IsEnabled` is `false`, or `Schedule.IsAccessAllowed()` is `false`. Claims are
  rebuilt fresh from the user plus `GetAdditionalClaimsAsync`, so role and claim changes
  take effect immediately.
- `Options.Username` is set (single-user mode) → the ticket username must still match,
  otherwise reject.
- Validation is delegate-based (`ValidateCredentialsAsync` or `Events.OnValidateCredentials`)
  → trust the stored claims. The password is not available, so re-validation is impossible.
- On rejection: delete the cookie and return `Fail(...)`, producing a 401 and the native
  dialog.

### Sign-out

`BasicAuthenticationHandler` implements `IAuthenticationSignOutHandler`. Calling
`HttpContext.SignOutAsync("Basic")` deletes the cookie and writes an audit entry. This
is the documented logout path.

## Security

- The cookie is a bearer credential. Defaults are `HttpOnly=true`, `Secure=Always`,
  `SameSite=Lax`, `Path=/`.
- The cookie is encrypted and signed by the Data Protection keyring. Multi-instance or
  containerized deployments must persist and share the keyring — otherwise cookies stop
  validating on restart or scale-out. The README documents this with
  `PersistKeysToFileSystem` / blob-storage examples.
- No password is ever stored in the ticket — username and claims only.
- Audit logging distinguishes the new paths: success reason `"remember-me-cookie"`;
  failure reasons `"Invalid remember-me cookie"`, `"User disabled"`, and
  `"Outside access schedule"`.

## Testing

New `BasicAuthGuard.Tests/RememberMeTests.cs`, xUnit, following the existing suites.

Protector:

- Round-trip preserves the principal, its claims, and the scheme.
- An expired ticket returns `null`.
- A tampered byte returns `null`.
- A value protected with a different purpose returns `null`.

Handler:

- A successful header authentication issues the cookie.
- The cookie alone authenticates a later request with no `Authorization` header.
- No cookie is issued when `RememberMe` is `null`.
- The `Authorization` header wins when both header and cookie are present.
- A disabled user is rejected and the cookie is cleared.
- A user outside their access schedule is rejected and the cookie is cleared.
- An expired cookie yields 401 with the `WWW-Authenticate` header.
- The IP-bypass path issues no cookie.
- `SlidingExpiration=true` re-issues the cookie; `false` does not.
- `SignOutAsync` clears the cookie.

## Documentation

- README: a "Remember Me" section covering configuration, the fact that the first native
  prompt still happens, the key-persistence warning, and the sign-out snippet.
- `BasicAuthGuard.Example/Program.cs`: enable the feature on one route plus a `/logout`
  endpoint.
- Version bump `1.0.3` → `1.1.0` (additive feature).

## Files

New: `Options/RememberMeOptions.cs`, `Services/RememberMeTicketProtector.cs`,
`BasicAuthGuard.Tests/RememberMeTests.cs`.

Edited: `Options/BasicAuthenticationOptions.cs`, `BasicAuthenticationHandler.cs`,
`Extensions/ServiceCollectionExtensions.cs`, `README.md`,
`BasicAuthGuard.Example/Program.cs`, `BasicAuthGuard/BasicAuthGuard.csproj`.

## Out of scope

- A custom HTML login form with a real checkbox.
- Remember-me support in `UrlBasicAuthenticationMiddleware`.
- A distributed or revocable server-side session store.
- Per-request or per-user opt-in (query string, delegate).
