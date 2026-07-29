# Remember Me Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** After a successful Basic authentication, issue a persistent encrypted cookie so the browser's native credential dialog does not reappear across browser restarts.

**Architecture:** A new `RememberMeOptions` turns the feature on. `RememberMeTicketProtector` serializes the `AuthenticationTicket` with `TicketSerializer.Default` and encrypts it with an `ITimeLimitedDataProtector`. `BasicAuthenticationHandler` issues that cookie after a successful header authentication, and — when a request arrives with no `Authorization` header — decrypts the cookie, revalidates the user against configured options, and authenticates from it.

**Tech Stack:** .NET 8/9/10, ASP.NET Core authentication handlers, ASP.NET Core Data Protection, xUnit + Shouldly + `Microsoft.AspNetCore.TestHost`.

**Spec:** `docs/superpowers/specs/2026-07-29-remember-me-design.md`

## Global Constraints

- Target frameworks: `net8.0;net9.0;net10.0`. Code must compile on all three — no APIs newer than .NET 8.
- `Nullable` is `enable`. No `#nullable disable`, no `!` on values that can genuinely be null.
- **No new NuGet packages.** `<FrameworkReference Include="Microsoft.AspNetCore.App" />` already supplies Data Protection, `TicketSerializer`, and `WebEncoders`.
- Root namespace is `AspNetCore.BasicAuthentication`. Options live in `AspNetCore.BasicAuthentication.Options`, services in `AspNetCore.BasicAuthentication.Services`. These two namespaces are in `GlobalUsings.cs` for the library project — inside `BasicAuthGuard/` you do not need to import `...Options`, `...Models`, `...Events`, or `...Events.Context`.
- Every public type and public member gets an XML `<summary>` doc comment. The project sets `EnforceExtendedAnalyzerRules`; the rest of the codebase documents everything, so match it.
- Tests use xUnit with `Shouldly` assertions (`value.ShouldBe(...)`), `[Fact]` methods, and the `// Arrange / // Act / // Assert` comment structure used by the existing suites.
- Build: `dotnet build BasicAuthGuard/BasicAuthGuard.csproj`
- Test one framework (fast): `dotnet test BasicAuthGuard.Tests/BasicAuthGuard.Tests.csproj -f net8.0`
- Filter a single test: `dotnet test BasicAuthGuard.Tests/BasicAuthGuard.Tests.csproj -f net8.0 --filter "FullyQualifiedName~RememberMe"`
- Work happens on branch `feature/remember-me`, already checked out.

---

## File Structure

**Create:**
- `BasicAuthGuard/Options/RememberMeOptions.cs` — cookie name, duration, sliding flag, cookie security attributes. Self-validating `Duration`.
- `BasicAuthGuard/Services/RememberMeTicketProtector.cs` — `IRememberMeTicketProtector` + implementation. Serialize/encrypt/decode the ticket. Knows nothing about HTTP.
- `BasicAuthGuard.Tests/RememberMeTests.cs` — protector unit tests and end-to-end handler tests.

**Modify:**
- `BasicAuthGuard/Options/BasicAuthenticationOptions.cs` — `RememberMe` property + `WithRememberMe(...)` fluent method.
- `BasicAuthGuard/BasicAuthenticationHandler.cs` — cookie issue, cookie authentication, revalidation, sign-out.
- `BasicAuthGuard/Extensions/ServiceCollectionExtensions.cs` — register Data Protection + the protector when the feature is on (two places: the `IServiceCollection` overload and the `AuthenticationBuilder` overload).
- `README.md` — "Remember Me" documentation section.
- `BasicAuthGuard.Example/Program.cs` — working example plus a logout endpoint.
- `BasicAuthGuard/BasicAuthGuard.csproj` — version `1.0.3` → `1.1.0`.

---

### Task 1: RememberMeOptions and fluent configuration

**Files:**
- Create: `BasicAuthGuard/Options/RememberMeOptions.cs`
- Modify: `BasicAuthGuard/Options/BasicAuthenticationOptions.cs`
- Test: `BasicAuthGuard.Tests/RememberMeTests.cs`

**Interfaces:**
- Consumes: nothing.
- Produces: `RememberMeOptions` with `CookieName` (string), `Duration` (TimeSpan), `SlidingExpiration` (bool), `SecurePolicy` (`CookieSecurePolicy`), `SameSite` (`SameSiteMode`), `Path` (string), `Domain` (string?), and `static readonly TimeSpan MaxDuration`. `BasicAuthenticationOptions.RememberMe` (`RememberMeOptions?`, null = disabled) and `BasicAuthenticationOptions.WithRememberMe(Action<RememberMeOptions>)` returning `BasicAuthenticationOptions`.

- [ ] **Step 1: Write the failing tests**

Create `BasicAuthGuard.Tests/RememberMeTests.cs`:

```csharp
using AspNetCore.BasicAuthentication.Options;
using Shouldly;

namespace AspNetCore.BasicAuthentication.Tests;

public class RememberMeTests
{
    [Fact]
    public void WithRememberMe_ShouldEnableFeatureWithDefaults()
    {
        // Arrange
        var options = new BasicAuthenticationOptions();

        // Act
        options.WithRememberMe(_ => { });

        // Assert
        options.RememberMe.ShouldNotBeNull();
        options.RememberMe!.CookieName.ShouldBe(".BasicAuthGuard.Remember");
        options.RememberMe.Duration.ShouldBe(TimeSpan.FromDays(14));
        options.RememberMe.SlidingExpiration.ShouldBeFalse();
    }

    [Fact]
    public void RememberMe_ShouldBeNullByDefault()
    {
        // Arrange & Act
        var options = new BasicAuthenticationOptions();

        // Assert
        options.RememberMe.ShouldBeNull();
    }

    [Fact]
    public void WithRememberMe_ShouldApplyConfiguration()
    {
        // Arrange
        var options = new BasicAuthenticationOptions();

        // Act
        options.WithRememberMe(remember =>
        {
            remember.CookieName = ".custom";
            remember.Duration = TimeSpan.FromDays(3);
            remember.SlidingExpiration = true;
        });

        // Assert
        options.RememberMe!.CookieName.ShouldBe(".custom");
        options.RememberMe.Duration.ShouldBe(TimeSpan.FromDays(3));
        options.RememberMe.SlidingExpiration.ShouldBeTrue();
    }

    [Fact]
    public void WithRememberMe_CalledTwice_ShouldReuseSameInstance()
    {
        // Arrange
        var options = new BasicAuthenticationOptions();

        // Act
        options.WithRememberMe(remember => remember.CookieName = ".first");
        options.WithRememberMe(remember => remember.SlidingExpiration = true);

        // Assert
        options.RememberMe!.CookieName.ShouldBe(".first");
        options.RememberMe.SlidingExpiration.ShouldBeTrue();
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(366)]
    public void Duration_OutOfRange_ShouldThrow(int days)
    {
        // Arrange
        var options = new RememberMeOptions();

        // Act & Assert
        Should.Throw<ArgumentOutOfRangeException>(() => options.Duration = TimeSpan.FromDays(days));
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `dotnet test BasicAuthGuard.Tests/BasicAuthGuard.Tests.csproj -f net8.0 --filter "FullyQualifiedName~RememberMeTests"`
Expected: compile error — `RememberMeOptions` does not exist, `BasicAuthenticationOptions` has no `RememberMe` / `WithRememberMe`.

- [ ] **Step 3: Create RememberMeOptions**

Create `BasicAuthGuard/Options/RememberMeOptions.cs`:

```csharp
using Microsoft.AspNetCore.Http;

namespace AspNetCore.BasicAuthentication.Options;

/// <summary>
/// Configuration for the persistent "remember me" cookie issued after a successful
/// Basic authentication.
/// </summary>
public class RememberMeOptions
{
    /// <summary>
    /// The longest lifetime a remember-me cookie may be configured with
    /// </summary>
    public static readonly TimeSpan MaxDuration = TimeSpan.FromDays(365);

    private TimeSpan _duration = TimeSpan.FromDays(14);

    /// <summary>
    /// Name of the cookie holding the encrypted authentication ticket
    /// </summary>
    public string CookieName { get; set; } = ".BasicAuthGuard.Remember";

    /// <summary>
    /// How long the cookie stays valid. Must be greater than zero and at most 365 days.
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException">
    /// Thrown when the value is not greater than zero or exceeds <see cref="MaxDuration"/>
    /// </exception>
    public TimeSpan Duration
    {
        get => _duration;
        set
        {
            if (value <= TimeSpan.Zero || value > MaxDuration)
            {
                throw new ArgumentOutOfRangeException(
                    nameof(value),
                    value,
                    "Duration must be greater than zero and at most 365 days.");
            }

            _duration = value;
        }
    }

    /// <summary>
    /// If true, the cookie is re-issued with a fresh lifetime on every request it authenticates
    /// </summary>
    public bool SlidingExpiration { get; set; }

    /// <summary>
    /// Controls whether the cookie is marked Secure. Defaults to <see cref="CookieSecurePolicy.Always"/>.
    /// </summary>
    public CookieSecurePolicy SecurePolicy { get; set; } = CookieSecurePolicy.Always;

    /// <summary>
    /// SameSite attribute of the cookie
    /// </summary>
    public SameSiteMode SameSite { get; set; } = SameSiteMode.Lax;

    /// <summary>
    /// Path the cookie is scoped to
    /// </summary>
    public string Path { get; set; } = "/";

    /// <summary>
    /// Optional domain the cookie is scoped to
    /// </summary>
    public string? Domain { get; set; }
}
```

The cookie is always `HttpOnly`; that is applied by the handler and is deliberately not configurable.

- [ ] **Step 4: Add the property and fluent method to BasicAuthenticationOptions**

In `BasicAuthGuard/Options/BasicAuthenticationOptions.cs`, add after the `AuditLog` property:

```csharp
    /// <summary>
    /// Persistent "remember me" cookie configuration. Null disables the feature.
    /// </summary>
    public RememberMeOptions? RememberMe { get; set; }
```

And add after the `WithAuditLog` method:

```csharp
    /// <summary>
    /// Configures the persistent "remember me" cookie
    /// </summary>
    public BasicAuthenticationOptions WithRememberMe(Action<RememberMeOptions> configure)
    {
        RememberMe ??= new RememberMeOptions();
        configure(RememberMe);
        return this;
    }
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `dotnet test BasicAuthGuard.Tests/BasicAuthGuard.Tests.csproj -f net8.0 --filter "FullyQualifiedName~RememberMeTests"`
Expected: 6 passed (the `[Theory]` counts as 3).

- [ ] **Step 6: Commit**

```bash
git add BasicAuthGuard/Options/RememberMeOptions.cs BasicAuthGuard/Options/BasicAuthenticationOptions.cs BasicAuthGuard.Tests/RememberMeTests.cs
git commit -m "feat: add RememberMeOptions and WithRememberMe configuration"
```

---

### Task 2: Ticket protector

**Files:**
- Create: `BasicAuthGuard/Services/RememberMeTicketProtector.cs`
- Modify: `BasicAuthGuard/Extensions/ServiceCollectionExtensions.cs`
- Test: `BasicAuthGuard.Tests/RememberMeTests.cs`

**Interfaces:**
- Consumes: `RememberMeOptions` from Task 1 (only to decide whether to register the service).
- Produces: `IRememberMeTicketProtector` with `string Protect(AuthenticationTicket ticket, TimeSpan lifetime)` and `AuthenticationTicket? Unprotect(string value)`; implementation `RememberMeTicketProtector(IDataProtectionProvider provider)` and constant `RememberMeTicketProtector.ProtectorPurpose`.

- [ ] **Step 1: Write the failing tests**

Append to `BasicAuthGuard.Tests/RememberMeTests.cs` (and add the new `using` lines at the top of the file):

```csharp
using System.Security.Claims;
using AspNetCore.BasicAuthentication.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
```

```csharp
    [Fact]
    public void Protector_RoundTrip_ShouldPreservePrincipal()
    {
        // Arrange
        var protector = new RememberMeTicketProtector(new EphemeralDataProtectionProvider());
        var ticket = CreateTicket("admin", "Admin");

        // Act
        var value = protector.Protect(ticket, TimeSpan.FromMinutes(5));
        var restored = protector.Unprotect(value);

        // Assert
        restored.ShouldNotBeNull();
        restored!.AuthenticationScheme.ShouldBe("BasicAuthGuard");
        restored.Principal.Identity!.Name.ShouldBe("admin");
        restored.Principal.IsInRole("Admin").ShouldBeTrue();
    }

    [Fact]
    public void Protector_ExpiredTicket_ShouldReturnNull()
    {
        // Arrange
        var protector = new RememberMeTicketProtector(new EphemeralDataProtectionProvider());
        var ticket = CreateTicket("admin", "Admin");

        // Act - a negative lifetime puts the expiry in the past
        var value = protector.Protect(ticket, TimeSpan.FromMinutes(-5));
        var restored = protector.Unprotect(value);

        // Assert
        restored.ShouldBeNull();
    }

    [Fact]
    public void Protector_TamperedValue_ShouldReturnNull()
    {
        // Arrange
        var protector = new RememberMeTicketProtector(new EphemeralDataProtectionProvider());
        var value = protector.Protect(CreateTicket("admin", "Admin"), TimeSpan.FromMinutes(5));
        var tampered = (value[0] == 'A' ? 'B' : 'A') + value.Substring(1);

        // Act
        var restored = protector.Unprotect(tampered);

        // Assert
        restored.ShouldBeNull();
    }

    [Fact]
    public void Protector_ValueFromDifferentKeyring_ShouldReturnNull()
    {
        // Arrange
        var issuer = new RememberMeTicketProtector(new EphemeralDataProtectionProvider());
        var other = new RememberMeTicketProtector(new EphemeralDataProtectionProvider());
        var value = issuer.Protect(CreateTicket("admin", "Admin"), TimeSpan.FromMinutes(5));

        // Act
        var restored = other.Unprotect(value);

        // Assert
        restored.ShouldBeNull();
    }

    [Theory]
    [InlineData("")]
    [InlineData("not-a-valid-cookie-value")]
    public void Protector_MalformedValue_ShouldReturnNull(string value)
    {
        // Arrange
        var protector = new RememberMeTicketProtector(new EphemeralDataProtectionProvider());

        // Act
        var restored = protector.Unprotect(value);

        // Assert
        restored.ShouldBeNull();
    }

    private static AuthenticationTicket CreateTicket(string username, string role)
    {
        var identity = new ClaimsIdentity(
            [new Claim(ClaimTypes.Name, username), new Claim(ClaimTypes.Role, role)],
            "BasicAuthGuard");
        return new AuthenticationTicket(new ClaimsPrincipal(identity), "BasicAuthGuard");
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `dotnet test BasicAuthGuard.Tests/BasicAuthGuard.Tests.csproj -f net8.0 --filter "FullyQualifiedName~RememberMeTests"`
Expected: compile error — `RememberMeTicketProtector` does not exist.

- [ ] **Step 3: Create the protector**

Create `BasicAuthGuard/Services/RememberMeTicketProtector.cs`:

```csharp
using System.Security.Cryptography;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.WebUtilities;

namespace AspNetCore.BasicAuthentication.Services;

/// <summary>
/// Protects and unprotects the authentication ticket stored in the remember-me cookie
/// </summary>
public interface IRememberMeTicketProtector
{
    /// <summary>
    /// Serializes and encrypts a ticket into a cookie-safe string that expires after
    /// the supplied lifetime
    /// </summary>
    string Protect(AuthenticationTicket ticket, TimeSpan lifetime);

    /// <summary>
    /// Decrypts a cookie value back into a ticket. Returns null when the value is
    /// malformed, tampered with, expired, or protected by a different keyring.
    /// </summary>
    AuthenticationTicket? Unprotect(string value);
}

/// <summary>
/// Data Protection based implementation of <see cref="IRememberMeTicketProtector"/>
/// </summary>
public sealed class RememberMeTicketProtector : IRememberMeTicketProtector
{
    /// <summary>
    /// Data Protection purpose string. Changing it invalidates every issued cookie.
    /// </summary>
    public const string ProtectorPurpose = "BasicAuthGuard.RememberMe.v1";

    private readonly ITimeLimitedDataProtector _protector;

    /// <summary>
    /// Creates a new instance
    /// </summary>
    public RememberMeTicketProtector(IDataProtectionProvider provider)
    {
        _protector = provider.CreateProtector(ProtectorPurpose).ToTimeLimitedDataProtector();
    }

    /// <inheritdoc />
    public string Protect(AuthenticationTicket ticket, TimeSpan lifetime)
    {
        var payload = TicketSerializer.Default.Serialize(ticket);
        var protectedBytes = _protector.Protect(payload, DateTimeOffset.UtcNow.Add(lifetime));
        return WebEncoders.Base64UrlEncode(protectedBytes);
    }

    /// <inheritdoc />
    public AuthenticationTicket? Unprotect(string value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return null;
        }

        try
        {
            var protectedBytes = WebEncoders.Base64UrlDecode(value);
            var payload = _protector.Unprotect(protectedBytes);
            return TicketSerializer.Default.Deserialize(payload);
        }
        catch (CryptographicException)
        {
            return null;
        }
        catch (FormatException)
        {
            return null;
        }
        catch (ArgumentException)
        {
            return null;
        }
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `dotnet test BasicAuthGuard.Tests/BasicAuthGuard.Tests.csproj -f net8.0 --filter "FullyQualifiedName~RememberMeTests"`
Expected: all pass, including the 6 from Task 1.

- [ ] **Step 5: Register the service**

In `BasicAuthGuard/Extensions/ServiceCollectionExtensions.cs` there are **two** overloads that inspect the configured options and register services — the `IServiceCollection` one (registers on `services`) and the `AuthenticationBuilder` one (registers on `builder.Services`). Add the same block to both, directly after their existing `if (options.AuditLog != null) { ... }` block.

In the `IServiceCollection` overload:

```csharp
        if (options.RememberMe != null)
        {
            services.AddDataProtection();
            services.TryAddSingleton<IRememberMeTicketProtector, RememberMeTicketProtector>();
        }
```

In the `AuthenticationBuilder` overload:

```csharp
        if (options.RememberMe != null)
        {
            builder.Services.AddDataProtection();
            builder.Services.TryAddSingleton<IRememberMeTicketProtector, RememberMeTicketProtector>();
        }
```

Add `using Microsoft.AspNetCore.DataProtection;` at the top of the file. `AddDataProtection()` is idempotent — calling it when the host already registered it changes nothing.

- [ ] **Step 6: Build to verify registration compiles**

Run: `dotnet build BasicAuthGuard/BasicAuthGuard.csproj -f net8.0`
Expected: build succeeded, 0 warnings.

- [ ] **Step 7: Commit**

```bash
git add BasicAuthGuard/Services/RememberMeTicketProtector.cs BasicAuthGuard/Extensions/ServiceCollectionExtensions.cs BasicAuthGuard.Tests/RememberMeTests.cs
git commit -m "feat: add remember-me ticket protector"
```

---

### Task 3: Issue the cookie after successful Basic authentication

**Files:**
- Modify: `BasicAuthGuard/BasicAuthenticationHandler.cs`
- Test: `BasicAuthGuard.Tests/RememberMeTests.cs`

**Interfaces:**
- Consumes: `IRememberMeTicketProtector.Protect` (Task 2), `Options.RememberMe` (Task 1).
- Produces: private handler members used by Task 4 and Task 5 — `Task<ClaimsPrincipal> BuildPrincipalAsync(string username, BasicAuthenticationUser? user)`, `void IssueRememberMeCookie(AuthenticationTicket ticket)`, `void DeleteRememberMeCookie()`, `CookieOptions BuildCookieOptions(RememberMeOptions options)`, and the constructor parameter `IRememberMeTicketProtector? ticketProtector` stored in field `_ticketProtector`.

- [ ] **Step 1: Write the failing tests**

Append to `BasicAuthGuard.Tests/RememberMeTests.cs`, plus these `using` lines at the top of the file:

```csharp
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using AspNetCore.BasicAuthentication.Extensions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
```

```csharp
    [Fact]
    public async Task SuccessfulAuth_WithRememberMeEnabled_ShouldSetCookie()
    {
        // Arrange
        using var host = await CreateHost(remember => remember.SecurePolicy = CookieSecurePolicy.None);
        var client = host.GetTestClient();
        client.DefaultRequestHeaders.Authorization = BasicHeader("admin", "password123");

        // Act
        var response = await client.GetAsync("/secure");

        // Assert
        response.StatusCode.ShouldBe(HttpStatusCode.OK);
        var setCookie = GetSetCookie(response, ".BasicAuthGuard.Remember");
        setCookie.ShouldNotBeNull();
        setCookie!.ShouldContain("httponly", Case.Insensitive);
        setCookie.ShouldContain("expires=", Case.Insensitive);
    }

    [Fact]
    public async Task SuccessfulAuth_WithRememberMeDisabled_ShouldNotSetCookie()
    {
        // Arrange
        using var host = await CreateHost(remember: null);
        var client = host.GetTestClient();
        client.DefaultRequestHeaders.Authorization = BasicHeader("admin", "password123");

        // Act
        var response = await client.GetAsync("/secure");

        // Assert
        response.StatusCode.ShouldBe(HttpStatusCode.OK);
        GetSetCookie(response, ".BasicAuthGuard.Remember").ShouldBeNull();
    }

    [Fact]
    public async Task FailedAuth_ShouldNotSetCookie()
    {
        // Arrange
        using var host = await CreateHost(remember => remember.SecurePolicy = CookieSecurePolicy.None);
        var client = host.GetTestClient();
        client.DefaultRequestHeaders.Authorization = BasicHeader("admin", "wrong-password");

        // Act
        var response = await client.GetAsync("/secure");

        // Assert
        response.StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
        GetSetCookie(response, ".BasicAuthGuard.Remember").ShouldBeNull();
    }

    private static AuthenticationHeaderValue BasicHeader(string username, string password) =>
        new("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes($"{username}:{password}")));

    private static string? GetSetCookie(HttpResponseMessage response, string cookieName)
    {
        if (!response.Headers.TryGetValues("Set-Cookie", out var values))
        {
            return null;
        }

        return values.FirstOrDefault(v => v.StartsWith(cookieName + "=", StringComparison.Ordinal));
    }

    /// <summary>
    /// Returns the "name=value" pair from a Set-Cookie header, ready to send back as a Cookie header.
    /// </summary>
    private static string CookiePair(string setCookieHeader) => setCookieHeader.Split(';')[0];

    private static async Task<IHost> CreateHost(Action<RememberMeOptions>? remember)
    {
        var host = new HostBuilder()
            .ConfigureWebHost(webBuilder =>
            {
                webBuilder.UseTestServer();
                webBuilder.ConfigureServices(services =>
                {
                    services.AddBasicAuthGuard(options =>
                    {
                        options.Username = "admin";
                        options.Password = "password123";

                        if (remember != null)
                        {
                            options.WithRememberMe(remember);
                        }
                    });
                    services.AddBasicAuthGuardPolicy();
                    services.AddAuthorization();
                    services.AddRouting();
                });
                webBuilder.Configure(app =>
                {
                    app.UseRouting();
                    app.UseAuthentication();
                    app.UseAuthorization();
                    app.UseEndpoints(endpoints =>
                    {
                        endpoints.MapGet("/secure", (HttpContext ctx) => ctx.User.Identity!.Name)
                            .RequireBasicAuth();
                    });
                });
            })
            .Build();

        await host.StartAsync();
        return host;
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `dotnet test BasicAuthGuard.Tests/BasicAuthGuard.Tests.csproj -f net8.0 --filter "FullyQualifiedName~RememberMeTests"`
Expected: `SuccessfulAuth_WithRememberMeEnabled_ShouldSetCookie` fails — cookie is null. The other two pass already.

- [ ] **Step 3: Add the protector dependency to the handler**

In `BasicAuthGuard/BasicAuthenticationHandler.cs`, add the field next to the existing ones and extend the constructor:

```csharp
    private readonly IPasswordHasher _passwordHasher;
    private readonly IRateLimiter? _rateLimiter;
    private readonly IAuditLogger _auditLogger;
    private readonly IRememberMeTicketProtector? _ticketProtector;

    /// <summary>
    /// Creates a new instance of the handler
    /// </summary>
    public BasicAuthenticationHandler(
        IOptionsMonitor<BasicAuthenticationOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder,
        IPasswordHasher passwordHasher,
        IRateLimiter? rateLimiter = null,
        IAuditLogger? auditLogger = null,
        IRememberMeTicketProtector? ticketProtector = null)
        : base(options, logger, encoder)
    {
        _passwordHasher = passwordHasher;
        _rateLimiter = rateLimiter;
        _auditLogger = auditLogger ?? NullAuditLogger.Instance;
        _ticketProtector = ticketProtector;
    }
```

The optional parameter keeps the existing constructor call sites working; ASP.NET Core's `ActivatorUtilities` fills it in when the service is registered.

- [ ] **Step 4: Extract principal building, then issue the cookie**

Still in `HandleAuthenticateAsync`, replace the block that starts at `// Build claims` and ends with `return AuthenticateResult.Success(ticket);` with:

```csharp
        var principal = await BuildPrincipalAsync(username, validationResult.User);
        var ticket = new AuthenticationTicket(principal, Scheme.Name);

        IssueRememberMeCookie(ticket);

        _auditLogger.LogSuccess(Context, username, Scheme.Name);

        var succeededContext = new AuthenticationSucceededContext(Context, Scheme, Options, username);
        await Options.Events.AuthenticationSucceededAsync(succeededContext);

        return AuthenticateResult.Success(ticket);
```

Then add these private methods below `ValidateCredentialsAsync`:

```csharp
    private async Task<ClaimsPrincipal> BuildPrincipalAsync(string username, BasicAuthenticationUser? user)
    {
        var claims = new List<Claim>
        {
            new(ClaimTypes.Name, username),
            new(ClaimTypes.NameIdentifier, username),
            new(ClaimTypes.AuthenticationMethod, "Basic")
        };

        if (user != null)
        {
            foreach (var role in user.Roles)
            {
                claims.Add(new Claim(ClaimTypes.Role, role));
            }

            claims.AddRange(user.Claims);
        }

        if (Options.GetAdditionalClaimsAsync != null)
        {
            var additionalClaims = await Options.GetAdditionalClaimsAsync(username, Context);
            claims.AddRange(additionalClaims);
        }

        return new ClaimsPrincipal(new ClaimsIdentity(claims, Scheme.Name));
    }

    private void IssueRememberMeCookie(AuthenticationTicket ticket)
    {
        var rememberMe = Options.RememberMe;
        if (rememberMe == null || _ticketProtector == null)
        {
            return;
        }

        var value = _ticketProtector.Protect(ticket, rememberMe.Duration);
        Response.Cookies.Append(rememberMe.CookieName, value, BuildCookieOptions(rememberMe));
    }

    private void DeleteRememberMeCookie()
    {
        var rememberMe = Options.RememberMe;
        if (rememberMe == null)
        {
            return;
        }

        var cookieOptions = BuildCookieOptions(rememberMe);
        cookieOptions.Expires = null;
        Response.Cookies.Delete(rememberMe.CookieName, cookieOptions);
    }

    private CookieOptions BuildCookieOptions(RememberMeOptions rememberMe) => new()
    {
        HttpOnly = true,
        Secure = rememberMe.SecurePolicy switch
        {
            CookieSecurePolicy.Always => true,
            CookieSecurePolicy.SameAsRequest => Request.IsHttps,
            _ => false
        },
        SameSite = rememberMe.SameSite,
        Path = rememberMe.Path,
        Domain = rememberMe.Domain,
        Expires = DateTimeOffset.UtcNow.Add(rememberMe.Duration),
        IsEssential = true
    };
```

`ClaimsPrincipal`, `Claim`, and `CookieOptions` need no new usings — `System.Security.Claims` and `Microsoft.AspNetCore.Http` are already imported in this file. Add `using AspNetCore.BasicAuthentication.Services;` only if it is not already there (it is — `IPasswordHasher` comes from it).

- [ ] **Step 5: Run tests to verify they pass**

Run: `dotnet test BasicAuthGuard.Tests/BasicAuthGuard.Tests.csproj -f net8.0 --filter "FullyQualifiedName~RememberMeTests"`
Expected: all pass.

- [ ] **Step 6: Run the whole suite — the refactor touched the shared success path**

Run: `dotnet test BasicAuthGuard.Tests/BasicAuthGuard.Tests.csproj -f net8.0`
Expected: all pre-existing tests still pass.

- [ ] **Step 7: Commit**

```bash
git add BasicAuthGuard/BasicAuthenticationHandler.cs BasicAuthGuard.Tests/RememberMeTests.cs
git commit -m "feat: issue remember-me cookie after successful basic auth"
```

---

### Task 4: Authenticate from the cookie, with revalidation

**Files:**
- Modify: `BasicAuthGuard/BasicAuthenticationHandler.cs`
- Test: `BasicAuthGuard.Tests/RememberMeTests.cs`

**Interfaces:**
- Consumes: `IRememberMeTicketProtector.Unprotect` (Task 2); `BuildPrincipalAsync`, `IssueRememberMeCookie`, `DeleteRememberMeCookie` (Task 3).
- Produces: private `Task<AuthenticateResult> AuthenticateFromRememberMeCookieAsync()` and `Task<RevalidationResult> RevalidateRememberMeAsync(string username, AuthenticationTicket ticket)` with the private record `RevalidationResult(bool IsValid, string? FailureReason, AuthenticationTicket? Ticket)`.

- [ ] **Step 1: Write the failing tests**

Append to `BasicAuthGuard.Tests/RememberMeTests.cs`. The multi-user host helper is new; add it too.

```csharp
    [Fact]
    public async Task CookieAlone_ShouldAuthenticateWithoutAuthorizationHeader()
    {
        // Arrange
        using var host = await CreateHost(remember => remember.SecurePolicy = CookieSecurePolicy.None);
        var client = host.GetTestClient();
        client.DefaultRequestHeaders.Authorization = BasicHeader("admin", "password123");
        var first = await client.GetAsync("/secure");
        var cookie = CookiePair(GetSetCookie(first, ".BasicAuthGuard.Remember")!);

        // Act - no Authorization header this time
        client.DefaultRequestHeaders.Authorization = null;
        client.DefaultRequestHeaders.Add("Cookie", cookie);
        var second = await client.GetAsync("/secure");

        // Assert
        second.StatusCode.ShouldBe(HttpStatusCode.OK);
        (await second.Content.ReadAsStringAsync()).ShouldBe("admin");
    }

    [Fact]
    public async Task NonSlidingCookie_ShouldNotBeReissuedOnCookieAuth()
    {
        // Arrange
        using var host = await CreateHost(remember => remember.SecurePolicy = CookieSecurePolicy.None);
        var client = host.GetTestClient();
        client.DefaultRequestHeaders.Authorization = BasicHeader("admin", "password123");
        var first = await client.GetAsync("/secure");
        var cookie = CookiePair(GetSetCookie(first, ".BasicAuthGuard.Remember")!);

        // Act
        client.DefaultRequestHeaders.Authorization = null;
        client.DefaultRequestHeaders.Add("Cookie", cookie);
        var second = await client.GetAsync("/secure");

        // Assert
        second.StatusCode.ShouldBe(HttpStatusCode.OK);
        GetSetCookie(second, ".BasicAuthGuard.Remember").ShouldBeNull();
    }

    [Fact]
    public async Task SlidingCookie_ShouldBeReissuedOnCookieAuth()
    {
        // Arrange
        using var host = await CreateHost(remember =>
        {
            remember.SecurePolicy = CookieSecurePolicy.None;
            remember.SlidingExpiration = true;
        });
        var client = host.GetTestClient();
        client.DefaultRequestHeaders.Authorization = BasicHeader("admin", "password123");
        var first = await client.GetAsync("/secure");
        var cookie = CookiePair(GetSetCookie(first, ".BasicAuthGuard.Remember")!);

        // Act
        client.DefaultRequestHeaders.Authorization = null;
        client.DefaultRequestHeaders.Add("Cookie", cookie);
        var second = await client.GetAsync("/secure");

        // Assert
        second.StatusCode.ShouldBe(HttpStatusCode.OK);
        GetSetCookie(second, ".BasicAuthGuard.Remember").ShouldNotBeNull();
    }

    [Fact]
    public async Task GarbageCookie_ShouldReturn401AndClearCookie()
    {
        // Arrange
        using var host = await CreateHost(remember => remember.SecurePolicy = CookieSecurePolicy.None);
        var client = host.GetTestClient();
        client.DefaultRequestHeaders.Add("Cookie", ".BasicAuthGuard.Remember=not-a-real-ticket");

        // Act
        var response = await client.GetAsync("/secure");

        // Assert
        response.StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
        response.Headers.WwwAuthenticate.ShouldNotBeEmpty();
        var setCookie = GetSetCookie(response, ".BasicAuthGuard.Remember");
        setCookie.ShouldNotBeNull();
        setCookie!.ShouldContain("expires=Thu, 01 Jan 1970", Case.Insensitive);
    }

    [Fact]
    public async Task AuthorizationHeader_ShouldWinOverCookie()
    {
        // Arrange - get a cookie for user1, then send it alongside user2's header
        using var host = await CreateMultiUserHost(remember => remember.SecurePolicy = CookieSecurePolicy.None);
        var client = host.GetTestClient();
        client.DefaultRequestHeaders.Authorization = BasicHeader("user1", "pass1");
        var first = await client.GetAsync("/secure");
        var cookie = CookiePair(GetSetCookie(first, ".BasicAuthGuard.Remember")!);

        // Act
        client.DefaultRequestHeaders.Authorization = BasicHeader("user2", "pass2");
        client.DefaultRequestHeaders.Add("Cookie", cookie);
        var second = await client.GetAsync("/secure");

        // Assert
        second.StatusCode.ShouldBe(HttpStatusCode.OK);
        (await second.Content.ReadAsStringAsync()).ShouldBe("user2");
    }

    [Fact]
    public async Task DisabledUser_ShouldRejectCookieAndClearIt()
    {
        // Arrange
        using var host = await CreateMultiUserHost(remember => remember.SecurePolicy = CookieSecurePolicy.None);
        var client = host.GetTestClient();
        client.DefaultRequestHeaders.Authorization = BasicHeader("user1", "pass1");
        var first = await client.GetAsync("/secure");
        var cookie = CookiePair(GetSetCookie(first, ".BasicAuthGuard.Remember")!);

        // Disable the user after the cookie was issued
        var options = host.Services
            .GetRequiredService<Microsoft.Extensions.Options.IOptionsMonitor<BasicAuthenticationOptions>>()
            .Get(BasicAuthenticationDefaults.AuthenticationScheme);
        options.Users.First(u => u.Username == "user1").IsEnabled = false;

        // Act
        client.DefaultRequestHeaders.Authorization = null;
        client.DefaultRequestHeaders.Add("Cookie", cookie);
        var second = await client.GetAsync("/secure");

        // Assert
        second.StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
        var setCookie = GetSetCookie(second, ".BasicAuthGuard.Remember");
        setCookie.ShouldNotBeNull();
        setCookie!.ShouldContain("expires=Thu, 01 Jan 1970", Case.Insensitive);
    }

    [Fact]
    public async Task CookieAuth_ShouldRestoreRolesFromCurrentConfiguration()
    {
        // Arrange
        using var host = await CreateMultiUserHost(remember => remember.SecurePolicy = CookieSecurePolicy.None);
        var client = host.GetTestClient();
        client.DefaultRequestHeaders.Authorization = BasicHeader("user1", "pass1");
        var first = await client.GetAsync("/secure");
        var cookie = CookiePair(GetSetCookie(first, ".BasicAuthGuard.Remember")!);

        // Act
        client.DefaultRequestHeaders.Authorization = null;
        client.DefaultRequestHeaders.Add("Cookie", cookie);
        var second = await client.GetAsync("/roles");

        // Assert
        second.StatusCode.ShouldBe(HttpStatusCode.OK);
        (await second.Content.ReadAsStringAsync()).ShouldBe("Admin");
    }

    [Fact]
    public async Task IpBypassedRequest_ShouldNotSetCookie()
    {
        // Arrange - TestServer requests come from ::1, which bypasses auth entirely
        using var host = await CreateIpBypassHost();
        var client = host.GetTestClient();

        // Act
        var response = await client.GetAsync("/secure");

        // Assert
        response.StatusCode.ShouldBe(HttpStatusCode.OK);
        GetSetCookie(response, ".BasicAuthGuard.Remember").ShouldBeNull();
    }

    private static async Task<IHost> CreateIpBypassHost()
    {
        var host = new HostBuilder()
            .ConfigureWebHost(webBuilder =>
            {
                webBuilder.UseTestServer();
                webBuilder.ConfigureServices(services =>
                {
                    services.AddBasicAuthGuard(options =>
                    {
                        options.Username = "admin";
                        options.Password = "password123";
                        options.WithIpWhitelist(whitelist =>
                        {
                            whitelist.AllowedRanges.Add("::1");
                            whitelist.AllowedRanges.Add("127.0.0.1");
                            whitelist.BypassAuthForAllowedIps = true;
                        });
                        options.WithRememberMe(remember => remember.SecurePolicy = CookieSecurePolicy.None);
                    });
                    services.AddBasicAuthGuardPolicy();
                    services.AddAuthorization();
                    services.AddRouting();
                });
                webBuilder.Configure(app =>
                {
                    app.UseRouting();
                    app.UseAuthentication();
                    app.UseAuthorization();
                    app.UseEndpoints(endpoints =>
                    {
                        endpoints.MapGet("/secure", (HttpContext ctx) => ctx.User.Identity!.Name)
                            .RequireBasicAuth();
                    });
                });
            })
            .Build();

        await host.StartAsync();
        return host;
    }

    private static async Task<IHost> CreateMultiUserHost(Action<RememberMeOptions> remember)
    {
        var host = new HostBuilder()
            .ConfigureWebHost(webBuilder =>
            {
                webBuilder.UseTestServer();
                webBuilder.ConfigureServices(services =>
                {
                    services.AddBasicAuthGuard(options =>
                    {
                        options.AddUser("user1", "pass1", ["Admin"]);
                        options.AddUser("user2", "pass2");
                        options.WithRememberMe(remember);
                    });
                    services.AddBasicAuthGuardPolicy();
                    services.AddAuthorization();
                    services.AddRouting();
                });
                webBuilder.Configure(app =>
                {
                    app.UseRouting();
                    app.UseAuthentication();
                    app.UseAuthorization();
                    app.UseEndpoints(endpoints =>
                    {
                        endpoints.MapGet("/secure", (HttpContext ctx) => ctx.User.Identity!.Name)
                            .RequireBasicAuth();

                        endpoints.MapGet("/roles", (HttpContext ctx) =>
                                string.Join(",", ctx.User.FindAll(System.Security.Claims.ClaimTypes.Role)
                                    .Select(c => c.Value)))
                            .RequireBasicAuth();
                    });
                });
            })
            .Build();

        await host.StartAsync();
        return host;
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `dotnet test BasicAuthGuard.Tests/BasicAuthGuard.Tests.csproj -f net8.0 --filter "FullyQualifiedName~RememberMeTests"`
Expected: the cookie-authentication tests fail with 401 — the handler still ignores the cookie. `AuthorizationHeader_ShouldWinOverCookie` passes already.

- [ ] **Step 3: Read the cookie when no Authorization header is present**

In `HandleAuthenticateAsync`, replace:

```csharp
        // Check for Authorization header
        if (!Request.Headers.ContainsKey("Authorization"))
        {
            return AuthenticateResult.NoResult();
        }
```

with:

```csharp
        // Check for Authorization header. A header always wins over the remember-me
        // cookie so a user can re-authenticate or switch identity.
        if (!Request.Headers.ContainsKey("Authorization"))
        {
            if (Options.RememberMe != null && _ticketProtector != null)
            {
                return await AuthenticateFromRememberMeCookieAsync();
            }

            return AuthenticateResult.NoResult();
        }
```

- [ ] **Step 4: Add the cookie authentication and revalidation methods**

Add below `BuildPrincipalAsync` in the handler:

```csharp
    private async Task<AuthenticateResult> AuthenticateFromRememberMeCookieAsync()
    {
        var rememberMe = Options.RememberMe!;
        var auditScheme = $"{Scheme.Name} (remember-me)";

        if (!Request.Cookies.TryGetValue(rememberMe.CookieName, out var cookieValue) ||
            string.IsNullOrEmpty(cookieValue))
        {
            return AuthenticateResult.NoResult();
        }

        var storedTicket = _ticketProtector!.Unprotect(cookieValue);
        if (storedTicket == null)
        {
            DeleteRememberMeCookie();
            _auditLogger.LogFailure(Context, null, "Invalid remember-me cookie", auditScheme);
            return AuthenticateResult.NoResult();
        }

        var username = storedTicket.Principal.FindFirst(ClaimTypes.Name)?.Value;
        if (string.IsNullOrEmpty(username))
        {
            DeleteRememberMeCookie();
            _auditLogger.LogFailure(Context, null, "Invalid remember-me cookie", auditScheme);
            return AuthenticateResult.NoResult();
        }

        var revalidation = await RevalidateRememberMeAsync(username, storedTicket);
        if (!revalidation.IsValid)
        {
            var reason = revalidation.FailureReason ?? "Invalid remember-me cookie";
            DeleteRememberMeCookie();
            _auditLogger.LogFailure(Context, username, reason, auditScheme);

            var failedContext = new AuthenticationFailedContext(Context, Scheme, Options, username, reason);
            await Options.Events.AuthenticationFailedAsync(failedContext);

            return AuthenticateResult.Fail(reason);
        }

        var ticket = revalidation.Ticket!;

        if (rememberMe.SlidingExpiration)
        {
            IssueRememberMeCookie(ticket);
        }

        _auditLogger.LogSuccess(Context, username, auditScheme);

        var succeededContext = new AuthenticationSucceededContext(Context, Scheme, Options, username);
        await Options.Events.AuthenticationSucceededAsync(succeededContext);

        return AuthenticateResult.Success(ticket);
    }

    private async Task<RevalidationResult> RevalidateRememberMeAsync(string username, AuthenticationTicket storedTicket)
    {
        // Multi-user configuration: re-check the user so disabling an account or a
        // closed schedule window takes effect immediately.
        if (Options.Users.Count > 0)
        {
            var user = Options.Users.FirstOrDefault(u =>
                string.Equals(u.Username, username, StringComparison.Ordinal));

            if (user == null)
            {
                return RevalidationResult.Failed("Invalid username");
            }

            if (!user.IsEnabled)
            {
                return RevalidationResult.Failed("User disabled");
            }

            if (user.Schedule != null && !user.Schedule.IsAccessAllowed())
            {
                return RevalidationResult.Failed("Outside access schedule");
            }

            var principal = await BuildPrincipalAsync(username, user);
            return RevalidationResult.Success(new AuthenticationTicket(principal, Scheme.Name));
        }

        // Single-user configuration
        if (!string.IsNullOrEmpty(Options.Username))
        {
            if (!string.Equals(Options.Username, username, StringComparison.Ordinal))
            {
                return RevalidationResult.Failed("Invalid username");
            }

            var principal = await BuildPrincipalAsync(username, null);
            return RevalidationResult.Success(new AuthenticationTicket(principal, Scheme.Name));
        }

        // Delegate-based validation: the password is not available, so the stored
        // claims are the only thing we can trust.
        return RevalidationResult.Success(new AuthenticationTicket(storedTicket.Principal, Scheme.Name));
    }
```

And add this record next to the existing private `ValidationResult` record at the bottom of the class:

```csharp
    private record RevalidationResult(bool IsValid, string? FailureReason, AuthenticationTicket? Ticket)
    {
        public static RevalidationResult Success(AuthenticationTicket ticket) => new(true, null, ticket);
        public static RevalidationResult Failed(string reason) => new(false, reason, null);
    }
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `dotnet test BasicAuthGuard.Tests/BasicAuthGuard.Tests.csproj -f net8.0 --filter "FullyQualifiedName~RememberMeTests"`
Expected: all pass.

- [ ] **Step 6: Run the full suite on all three frameworks**

Run: `dotnet test BasicAuthGuard.Tests/BasicAuthGuard.Tests.csproj`
Expected: all pass on net8.0, net9.0, and net10.0.

- [ ] **Step 7: Commit**

```bash
git add BasicAuthGuard/BasicAuthenticationHandler.cs BasicAuthGuard.Tests/RememberMeTests.cs
git commit -m "feat: authenticate from remember-me cookie with revalidation"
```

---

### Task 5: Sign-out clears the cookie

**Files:**
- Modify: `BasicAuthGuard/BasicAuthenticationHandler.cs`
- Test: `BasicAuthGuard.Tests/RememberMeTests.cs`

**Interfaces:**
- Consumes: `DeleteRememberMeCookie()` (Task 3).
- Produces: `BasicAuthenticationHandler` implements `IAuthenticationSignOutHandler`, so `HttpContext.SignOutAsync(BasicAuthenticationDefaults.AuthenticationScheme)` clears the cookie.

- [ ] **Step 1: Write the failing test**

Append to `BasicAuthGuard.Tests/RememberMeTests.cs`:

```csharp
    [Fact]
    public async Task SignOut_ShouldClearCookie()
    {
        // Arrange
        using var host = await CreateHostWithLogout();
        var client = host.GetTestClient();
        client.DefaultRequestHeaders.Authorization = BasicHeader("admin", "password123");
        var first = await client.GetAsync("/secure");
        var cookie = CookiePair(GetSetCookie(first, ".BasicAuthGuard.Remember")!);

        // Act
        client.DefaultRequestHeaders.Authorization = null;
        client.DefaultRequestHeaders.Add("Cookie", cookie);
        var response = await client.GetAsync("/logout");

        // Assert
        var setCookie = GetSetCookie(response, ".BasicAuthGuard.Remember");
        setCookie.ShouldNotBeNull();
        setCookie!.ShouldContain("expires=Thu, 01 Jan 1970", Case.Insensitive);
    }

    private static async Task<IHost> CreateHostWithLogout()
    {
        var host = new HostBuilder()
            .ConfigureWebHost(webBuilder =>
            {
                webBuilder.UseTestServer();
                webBuilder.ConfigureServices(services =>
                {
                    services.AddBasicAuthGuard(options =>
                    {
                        options.Username = "admin";
                        options.Password = "password123";
                        options.WithRememberMe(remember => remember.SecurePolicy = CookieSecurePolicy.None);
                    });
                    services.AddBasicAuthGuardPolicy();
                    services.AddAuthorization();
                    services.AddRouting();
                });
                webBuilder.Configure(app =>
                {
                    app.UseRouting();
                    app.UseAuthentication();
                    app.UseAuthorization();
                    app.UseEndpoints(endpoints =>
                    {
                        endpoints.MapGet("/secure", (HttpContext ctx) => ctx.User.Identity!.Name)
                            .RequireBasicAuth();

                        endpoints.MapGet("/logout", async (HttpContext ctx) =>
                        {
                            await ctx.SignOutAsync(BasicAuthenticationDefaults.AuthenticationScheme);
                            return "signed out";
                        });
                    });
                });
            })
            .Build();

        await host.StartAsync();
        return host;
    }
```

`SignOutAsync` needs `using Microsoft.AspNetCore.Authentication;` — already added in Task 2.

- [ ] **Step 2: Run test to verify it fails**

Run: `dotnet test BasicAuthGuard.Tests/BasicAuthGuard.Tests.csproj -f net8.0 --filter "FullyQualifiedName~SignOut_ShouldClearCookie"`
Expected: FAIL — `InvalidOperationException: ... no IAuthenticationSignOutHandler is configured to handle sign out for the scheme: BasicAuthGuard`.

- [ ] **Step 3: Implement the sign-out handler**

Change the class declaration in `BasicAuthGuard/BasicAuthenticationHandler.cs`:

```csharp
public class BasicAuthenticationHandler : AuthenticationHandler<BasicAuthenticationOptions>, IAuthenticationSignOutHandler
```

And add this method after `HandleForbiddenAsync`:

```csharp
    /// <summary>
    /// Clears the remember-me cookie. Basic authentication itself is stateless, so this
    /// is the only server-side state a sign-out can remove.
    /// </summary>
    public Task SignOutAsync(AuthenticationProperties? properties)
    {
        DeleteRememberMeCookie();

        var username = Context.User.Identity?.Name;
        if (!string.IsNullOrEmpty(username))
        {
            _auditLogger.LogSuccess(Context, username, $"{Scheme.Name} (sign-out)");
        }

        return Task.CompletedTask;
    }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `dotnet test BasicAuthGuard.Tests/BasicAuthGuard.Tests.csproj -f net8.0 --filter "FullyQualifiedName~SignOut_ShouldClearCookie"`
Expected: PASS

- [ ] **Step 5: Run the full suite**

Run: `dotnet test BasicAuthGuard.Tests/BasicAuthGuard.Tests.csproj -f net8.0`
Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add BasicAuthGuard/BasicAuthenticationHandler.cs BasicAuthGuard.Tests/RememberMeTests.cs
git commit -m "feat: clear remember-me cookie on sign-out"
```

---

### Task 6: Documentation, example, version bump

**Files:**
- Modify: `README.md`
- Modify: `BasicAuthGuard.Example/Program.cs`
- Modify: `BasicAuthGuard/BasicAuthGuard.csproj`

**Interfaces:**
- Consumes: everything from Tasks 1-5.
- Produces: nothing consumed by later tasks.

- [ ] **Step 1: Add the README section**

Read `README.md` first and place this section alongside the other feature sections (Rate Limiting, IP Whitelisting, Audit Logging), matching their heading level and formatting:

````markdown
## Remember Me

The browser's native Basic-auth dialog is browser chrome — a server cannot add a
"remember me" checkbox to it, and browsers forget Basic credentials when they close.

`WithRememberMe` closes that gap: after a successful authentication, BasicAuthGuard
issues an encrypted, HttpOnly cookie. Later requests that carry no `Authorization`
header authenticate from that cookie, so the dialog does not come back until the
cookie expires.

```csharp
builder.Services.AddBasicAuthGuard(options =>
{
    options.Username = "admin";
    options.Password = "password123";

    options.WithRememberMe(remember =>
    {
        remember.Duration = TimeSpan.FromDays(30);   // default: 14 days, max: 365
        remember.SlidingExpiration = true;           // default: false
        remember.CookieName = ".BasicAuthGuard.Remember";
        remember.SameSite = SameSiteMode.Lax;
        remember.SecurePolicy = CookieSecurePolicy.Always;
    });
});
```

Behaviour:

- The native dialog still appears the **first** time. The cookie is issued only after
  those credentials are accepted.
- An `Authorization` header always wins over the cookie, so a user can re-authenticate
  or switch identity at any time.
- When users are configured through `AddUser`, every cookie-authenticated request
  re-checks the user: disabling an account or falling outside an `AccessSchedule`
  rejects the cookie immediately and clears it. Roles and claims are rebuilt from the
  current configuration.
- When credentials are validated through `ValidateCredentialsAsync` or the
  `OnValidateCredentials` event, the password is not available on the cookie path, so
  the claims stored in the cookie are trusted until it expires.
- The cookie is always `HttpOnly` and is `Secure` by default. It is encrypted and
  signed with ASP.NET Core Data Protection, and the expiry is enforced server-side.

### Signing out

```csharp
app.MapGet("/logout", async (HttpContext context) =>
{
    await context.SignOutAsync(BasicAuthenticationDefaults.AuthenticationScheme);
    return Results.Ok("Signed out");
});
```

This clears the cookie. The browser may still hold cached Basic credentials for the
current session — that part is browser-controlled and closing the browser clears it.

### Persist your Data Protection keys

The cookie is encrypted with the app's Data Protection keyring. On a single machine
with default settings this just works. **If you run multiple instances, containers, or
anything with an ephemeral filesystem, persist and share the keyring** — otherwise
every restart or scale-out invalidates all remember-me cookies and users get prompted
again:

```csharp
builder.Services.AddDataProtection()
    .PersistKeysToFileSystem(new DirectoryInfo("/var/keys"))
    .SetApplicationName("MyApp");
```
````

- [ ] **Step 2: Update the example app**

Read `BasicAuthGuard.Example/Program.cs`, then enable remember-me on the existing
`AddBasicAuthGuard` configuration and add a logout endpoint next to the other endpoints:

```csharp
    options.WithRememberMe(remember =>
    {
        remember.Duration = TimeSpan.FromDays(30);
        remember.SlidingExpiration = true;
    });
```

```csharp
app.MapGet("/logout", async (HttpContext context) =>
{
    await context.SignOutAsync(BasicAuthenticationDefaults.AuthenticationScheme);
    return Results.Ok("Signed out - remember-me cookie cleared");
});
```

Add `using Microsoft.AspNetCore.Authentication;` if `SignOutAsync` does not resolve.

- [ ] **Step 3: Bump the version**

In `BasicAuthGuard/BasicAuthGuard.csproj`, change `<Version>1.0.3</Version>` to `<Version>1.1.0</Version>`.

- [ ] **Step 4: Verify everything builds and passes**

Run: `dotnet build && dotnet test BasicAuthGuard.Tests/BasicAuthGuard.Tests.csproj`
Expected: solution builds with 0 warnings, all tests pass on all three target frameworks.

- [ ] **Step 5: Commit**

```bash
git add README.md BasicAuthGuard.Example/Program.cs BasicAuthGuard/BasicAuthGuard.csproj
git commit -m "docs: document remember-me and bump version to 1.1.0"
```

---

## Notes on spec deviations

- The spec asks for audit entries distinguishing the cookie path. `IAuditLogger` has no
  field for that, so the cookie path passes `"{scheme} (remember-me)"` and the sign-out
  path passes `"{scheme} (sign-out)"` as the `scheme` argument rather than adding a
  breaking overload to the public `IAuditLogger` interface.
- The spec's cookie-expiry test is covered at the protector level
  (`Protector_ExpiredTicket_ShouldReturnNull`) instead of the handler level, to avoid a
  sleep-based test. The handler-level `GarbageCookie_ShouldReturn401AndClearCookie` test
  covers the same "unusable cookie" branch.
