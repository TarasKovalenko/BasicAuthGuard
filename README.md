# BasicAuthGuard

[![.NET](https://img.shields.io/badge/.NET-8.0%20|%209.0%20|%2010.0-512BD4)](https://dotnet.microsoft.com/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Made in Ukraine](https://img.shields.io/badge/made_in-ukraine-ffd700.svg?labelColor=0057b7)](https://taraskovalenko.github.io/)

Zero-config Basic Authentication for ASP.NET Core. Inline credentials, per-endpoint auth, URL-based auth, rate limiting, IP whitelisting, and audit logging out of the box.

## Features

- 🔐 **Simple Setup** - One-liner configuration with inline credentials
- 🎯 **Per-Endpoint Auth** - Different credentials for different endpoints
- 🌐 **URL-Based Auth** - Protect URLs by pattern with middleware
- 👥 **Multi-User Support** - Configure multiple users with roles and claims
- ⏱️ **Rate Limiting** - Protect against brute force attacks
- 🌍 **IP Whitelisting** - Allow/block specific IP addresses or CIDR ranges
- 📝 **Audit Logging** - Track authentication attempts
- 🔒 **Password Hashing** - Support for SHA256, SHA512, and BCrypt
- 📅 **Access Schedules** - Time-based access restrictions
- 🎪 **Event Hooks** - Custom logic for authentication lifecycle

## Terms of use

By using this project or its source code, for any purpose and in any shape or form, you grant your **implicit agreement** to all of the following statements:

- You unequivocally condemn Russia and its military aggression against Ukraine
- You recognize that Russia is an occupant that unlawfully invaded a sovereign state
- You agree that [Russia is a terrorist state](https://www.europarl.europa.eu/doceo/document/RC-9-2022-0482_EN.html)
- You fully support Ukraine's territorial integrity, including its claims over [temporarily occupied territories](https://en.wikipedia.org/wiki/Russian-occupied_territories_of_Ukraine)
- You reject false narratives perpetuated by Russian state propaganda

To learn more about the war and how you can help, [click here](https://war.ukraine.ua/). Glory to Ukraine! 🇺🇦

## Installation

```bash
dotnet add package BasicAuthGuard
```

## Quick Start

### Simplest Usage

```csharp
var builder = WebApplication.CreateBuilder(args);

// Add basic auth with inline credentials
builder.Services.AddBasicAuthGuard("admin", "password");

var app = builder.Build();

// Protect an endpoint
app.MapGet("/api/secret", () => "Secret data")
   .RequireBasicAuth();

app.Run();
```

### Per-Endpoint Credentials

```csharp
app.MapGet("/api/users", () => GetUsers())
   .RequireBasicAuth("user", "userpass");

app.MapGet("/api/admin", () => GetAdminData())
   .RequireBasicAuth("admin", "adminpass", realm: "Admin Area");
```

### URL-Based Authentication (Middleware)

Protect endpoints by URL pattern without modifying endpoint definitions:

```csharp
var app = builder.Build();

// Simple: protect a single URL
app.AddBasicAuthGuard("/health", "healthuser", "healthpass");

// With realm
app.AddBasicAuthGuard("/api/admin/*", "admin", "adminpass", "Admin Area");

// Multiple patterns at once
app.UseBasicAuthGuard(auth =>
{
    auth.AddPattern("/metrics", "metrics", "metricspass");
    auth.AddPattern("/api/internal/**", options =>
    {
        options.Username = "internal";
        options.Password = "internalpass";
        options.Realm = "Internal API";
        options.Roles.Add("InternalUser");
    });
});

// Your endpoints (no auth attributes needed)
app.MapGet("/health", () => Results.Ok(new { status = "healthy" }));
app.MapGet("/metrics", () => GetMetrics());
```

**URL Pattern Wildcards:**
- `*` - Matches any single path segment (e.g., `/api/*` matches `/api/users` but not `/api/users/1`)
- `**` - Matches any path including nested segments (e.g., `/api/**` matches `/api/users/1/orders`)

---

## Table of Contents

- [Service Registration](#service-registration)
- [Endpoint Protection](#endpoint-protection)
- [URL-Based Protection](#url-based-protection)
- [Multi-User Configuration](#multi-user-configuration)
- [Password Hashing](#password-hashing)
- [Rate Limiting](#rate-limiting)
- [IP Whitelisting](#ip-whitelisting)
- [Audit Logging](#audit-logging)
- [Access Schedules](#access-schedules)
- [Custom Validation](#custom-validation)
- [Events](#events)
- [Configuration Options Reference](#configuration-options-reference)

---

## Service Registration

### AddBasicAuthGuard (IServiceCollection)

Register basic authentication in the DI container.

```csharp
// Inline credentials
builder.Services.AddBasicAuthGuard("username", "password");

// With realm
builder.Services.AddBasicAuthGuard("username", "password", "MyRealm");

// With configuration delegate
builder.Services.AddBasicAuthGuard(options =>
{
    options.Username = "admin";
    options.Password = "password";
    options.Realm = "Protected Area";
});

// With custom scheme name
builder.Services.AddBasicAuthGuard("CustomScheme", options =>
{
    options.Username = "admin";
    options.Password = "password";
});

// From configuration section
builder.Services.AddBasicAuthGuard(builder.Configuration.GetSection("BasicAuth"));
```

### AddBasicAuthGuardPolicy

Add an authorization policy for basic auth.

```csharp
builder.Services.AddBasicAuthGuard("admin", "password");
builder.Services.AddBasicAuthGuardPolicy(); // Default policy name

// Custom policy name
builder.Services.AddBasicAuthGuardPolicy("MyBasicAuthPolicy", "CustomScheme");
```

---

## Endpoint Protection

### RequireBasicAuth (Endpoint Extension)

Protect individual endpoints with basic authentication.

```csharp
// Use global credentials (from AddBasicAuthGuard)
app.MapGet("/api/data", () => "data")
   .RequireBasicAuth();

// Per-endpoint credentials
app.MapGet("/api/users", () => GetUsers())
   .RequireBasicAuth("user", "userpass");

// With realm
app.MapGet("/api/admin", () => GetAdminData())
   .RequireBasicAuth("admin", "adminpass", realm: "Admin Area");

// With full configuration
app.MapGet("/api/special", () => "special")
   .RequireBasicAuth(options =>
   {
       options.Username = "special";
       options.Password = "specialpass";
       options.Realm = "Special Area";
       options.Roles.Add("SpecialUser");
       options.Claims.Add(new Claim("department", "IT"));
   });
```

### EndpointBasicAuthenticationOptions

Options for per-endpoint authentication:

| Property | Type | Description |
|----------|------|-------------|
| `Username` | `string?` | Required username |
| `Password` | `string?` | Required password |
| `Realm` | `string?` | Realm for WWW-Authenticate header |
| `ValidateCredentialsAsync` | `Func<string, string, HttpContext, Task<bool>>?` | Custom validation delegate |
| `Claims` | `IList<Claim>` | Additional claims to add |
| `Roles` | `IList<string>` | Roles to assign |

---

## URL-Based Protection

Protect URLs using middleware without modifying endpoint definitions.

### AddBasicAuthGuard (IApplicationBuilder)

```csharp
// Simple credentials
app.AddBasicAuthGuard("/health", "user", "pass");

// With realm
app.AddBasicAuthGuard("/api/admin/*", "admin", "adminpass", "Admin Area");

// With full configuration
app.AddBasicAuthGuard("/api/internal", options =>
{
    options.Username = "internal";
    options.Password = "internalpass";
    options.Realm = "Internal API";
    options.Roles.Add("InternalUser");
    options.CaseInsensitiveUrlMatching = true;
});
```

### UseBasicAuthGuard (Builder Pattern)

Configure multiple URL patterns at once:

```csharp
app.UseBasicAuthGuard(auth =>
{
    // Simple pattern
    auth.AddPattern("/health", "health", "healthpass");
    
    // Wildcard patterns
    auth.AddPattern("/api/v1/*", "apiv1", "apiv1pass");
    auth.AddPattern("/api/v2/**", "apiv2", "apiv2pass");
    
    // With full options
    auth.AddPattern("/admin/**", options =>
    {
        options.Username = "admin";
        options.Password = "adminpass";
        options.Realm = "Administration";
        options.Roles.Add("Admin");
        options.ValidateCredentialsAsync = async (user, pass, ctx) =>
        {
            // Custom validation logic
            return user == "admin" && pass == "adminpass";
        };
    });
});
```

### UrlBasicAuthenticationOptions

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `UrlPattern` | `string` | `""` | URL pattern to match |
| `Username` | `string?` | `null` | Required username |
| `Password` | `string?` | `null` | Required password |
| `Realm` | `string?` | `null` | Realm for WWW-Authenticate header |
| `ValidateCredentialsAsync` | `Func<...>?` | `null` | Custom validation delegate |
| `Claims` | `IList<Claim>` | `[]` | Additional claims |
| `Roles` | `IList<string>` | `[]` | Roles to assign |
| `CaseInsensitiveUrlMatching` | `bool` | `true` | Case-insensitive URL matching |

---

## Multi-User Configuration

Configure multiple users with different credentials, roles, and permissions.

```csharp
builder.Services.AddBasicAuthGuard(options =>
{
    // Add users with fluent API
    options.AddUser("admin", "adminpass", 
        roles: ["Admin", "User"],
        claims: [new Claim("department", "IT")]);
    
    options.AddUser("user", "userpass", 
        roles: ["User"]);
    
    options.AddUser("readonly", "readonlypass",
        roles: ["Reader"]);
});
```

### BasicAuthenticationUser

| Property | Type | Description |
|----------|------|-------------|
| `Username` | `string` | Username for authentication |
| `Password` | `string?` | Plain text password |
| `PasswordHash` | `string?` | Hashed password |
| `Roles` | `IReadOnlyList<string>` | Assigned roles |
| `Claims` | `IReadOnlyList<Claim>` | Additional claims |
| `IsEnabled` | `bool` | Whether account is active |
| `Schedule` | `AccessSchedule?` | Time-based restrictions |

---

## Password Hashing

Store passwords securely using hashing algorithms.

### Supported Algorithms

| Algorithm | Enum Value | Description |
|-----------|------------|-------------|
| None | `PasswordHashAlgorithm.None` | Plain text (not recommended) |
| SHA256 | `PasswordHashAlgorithm.SHA256` | SHA-256 hash |
| SHA512 | `PasswordHashAlgorithm.SHA512` | SHA-512 hash |
| BCrypt | `PasswordHashAlgorithm.BCrypt` | BCrypt (PBKDF2-based, recommended) |

### Usage

```csharp
builder.Services.AddBasicAuthGuard(options =>
{
    options.HashAlgorithm = PasswordHashAlgorithm.BCrypt;
    
    // Add user with pre-hashed password
    options.AddUserWithHash(
        username: "admin",
        passwordHash: "hashed_password_here",
        algorithm: PasswordHashAlgorithm.BCrypt,
        roles: ["Admin"]);
});
```

### IPasswordHasher Service

You can also inject `IPasswordHasher` to hash passwords programmatically:

```csharp
public class MyService
{
    private readonly IPasswordHasher _hasher;
    
    public MyService(IPasswordHasher hasher) => _hasher = hasher;
    
    public string HashPassword(string password)
    {
        return _hasher.Hash(password, PasswordHashAlgorithm.BCrypt);
    }
    
    public bool VerifyPassword(string password, string hash)
    {
        return _hasher.Verify(password, hash, PasswordHashAlgorithm.BCrypt);
    }
}
```

---

## Rate Limiting

Protect against brute force attacks by limiting failed authentication attempts.

```csharp
builder.Services.AddBasicAuthGuard(options =>
{
    options.Username = "admin";
    options.Password = "password";
    
    options.WithRateLimiting(rate =>
    {
        rate.MaxFailedAttempts = 5;           // Lock after 5 failures
        rate.LockoutDuration = TimeSpan.FromMinutes(15);  // Lock for 15 minutes
        rate.AttemptWindow = TimeSpan.FromMinutes(5);     // Count failures within 5 min window
        rate.PerIp = true;                    // Track per IP address
        rate.IncludeUsername = true;          // Include username in lockout key
        rate.LockoutMessage = "Too many failed attempts. Please try again later.";
    });
});
```

### RateLimitOptions

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `MaxFailedAttempts` | `int` | `5` | Max failures before lockout |
| `LockoutDuration` | `TimeSpan` | `15 min` | Duration of lockout |
| `AttemptWindow` | `TimeSpan` | `5 min` | Window for counting failures |
| `PerIp` | `bool` | `true` | Track per IP address |
| `IncludeUsername` | `bool` | `true` | Include username in lockout key |
| `LockoutMessage` | `string?` | `null` | Custom lockout message |

---

## IP Whitelisting

Control access based on client IP addresses.

```csharp
builder.Services.AddBasicAuthGuard(options =>
{
    options.Username = "admin";
    options.Password = "password";
    
    options.WithIpWhitelist(ip =>
    {
        // Allow specific IPs or CIDR ranges
        ip.AllowedRanges = ["192.168.1.0/24", "10.0.0.1", "::1"];
        
        // Block specific IPs
        ip.BlockedRanges = ["192.168.1.100"];
        
        // Skip auth entirely for whitelisted IPs
        ip.BypassAuthForAllowedIps = true;
        
        // Reject if not in whitelist (when AllowedRanges is set)
        ip.RejectIfNotWhitelisted = true;
        
        // Custom message for blocked IPs
        ip.BlockedMessage = "Access denied from your IP address.";
    });
});
```

### IpWhitelistOptions

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `AllowedRanges` | `IList<string>` | `[]` | Allowed IPs/CIDR ranges |
| `BlockedRanges` | `IList<string>` | `[]` | Blocked IPs/CIDR ranges |
| `BypassAuthForAllowedIps` | `bool` | `false` | Skip auth for allowed IPs |
| `RejectIfNotWhitelisted` | `bool` | `true` | Reject if not whitelisted |
| `BlockedMessage` | `string?` | `null` | Custom blocked message |

---

## Audit Logging

Track all authentication attempts for security monitoring.

```csharp
builder.Services.AddBasicAuthGuard(options =>
{
    options.Username = "admin";
    options.Password = "password";
    
    options.WithAuditLog(audit =>
    {
        audit.Enabled = true;
        audit.SuccessLogLevel = LogLevel.Information;
        audit.FailureLogLevel = LogLevel.Warning;
        audit.IncludeIpAddress = true;
        audit.IncludeUserAgent = true;
        audit.IncludeRequestPath = true;
        audit.IncludeUsernameOnFailure = true;
        
        // Custom log message templates
        audit.SuccessMessageTemplate = 
            "Auth success: {Username} from {IpAddress} accessing {Path}";
        audit.FailureMessageTemplate = 
            "Auth failed: {Username} from {IpAddress} - {Reason}";
    });
});
```

### AuditLogOptions

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `Enabled` | `bool` | `true` | Enable audit logging |
| `SuccessLogLevel` | `LogLevel` | `Information` | Log level for success |
| `FailureLogLevel` | `LogLevel` | `Warning` | Log level for failures |
| `IncludeIpAddress` | `bool` | `true` | Include client IP |
| `IncludeUserAgent` | `bool` | `false` | Include User-Agent header |
| `IncludeRequestPath` | `bool` | `true` | Include request path |
| `IncludeUsernameOnFailure` | `bool` | `true` | Include username on failures |
| `SuccessMessageTemplate` | `string?` | `null` | Custom success message |
| `FailureMessageTemplate` | `string?` | `null` | Custom failure message |

**Available Placeholders:** `{Username}`, `{IpAddress}`, `{UserAgent}`, `{Path}`, `{Scheme}`, `{Reason}`

---

## Access Schedules

Restrict user access to specific days and hours.

```csharp
builder.Services.AddBasicAuthGuard(options =>
{
    // Add user with schedule restrictions
    options.AddUserWithSchedule(
        username: "contractor",
        password: "contractorpass",
        schedule: new AccessSchedule
        {
            AllowedDays = [DayOfWeek.Monday, DayOfWeek.Tuesday, 
                          DayOfWeek.Wednesday, DayOfWeek.Thursday, 
                          DayOfWeek.Friday],
            AllowedFromHour = 9,   // 9 AM
            AllowedToHour = 17,    // 5 PM
            TimeZone = TimeZoneInfo.FindSystemTimeZoneById("Eastern Standard Time")
        },
        roles: ["Contractor"]);
});
```

### AccessSchedule

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `AllowedDays` | `IReadOnlyList<DayOfWeek>` | `[]` | Allowed days (empty = all) |
| `AllowedFromHour` | `int?` | `null` | Start hour (0-23) |
| `AllowedToHour` | `int?` | `null` | End hour (0-23) |
| `TimeZone` | `TimeZoneInfo` | `UTC` | Timezone for evaluation |

---

## Custom Validation

Implement custom credential validation logic.

### Using Delegate

```csharp
builder.Services.AddBasicAuthGuard(options =>
{
    options.ValidateCredentialsAsync = async (username, password, context) =>
    {
        // Custom validation logic (e.g., database lookup)
        var user = await _userService.ValidateAsync(username, password);
        return user != null;
    };
});
```

### Using Events

```csharp
builder.Services.AddBasicAuthGuard(options =>
{
    options.Events.OnValidateCredentials = async context =>
    {
        // Access username and password
        var username = context.Username;
        var password = context.Password;
        
        // Validate against your user store
        var isValid = await ValidateUserAsync(username, password);
        
        if (isValid)
        {
            // Add custom claims
            context.ValidationSucceeded([
                new Claim("custom-claim", "value"),
                new Claim(ClaimTypes.Role, "CustomRole")
            ]);
        }
        else
        {
            context.ValidationFailed("Invalid credentials");
        }
    };
});
```

### Adding Claims After Authentication

```csharp
builder.Services.AddBasicAuthGuard(options =>
{
    options.Username = "admin";
    options.Password = "password";
    
    options.GetAdditionalClaimsAsync = async (username, context) =>
    {
        // Fetch additional claims from database
        var userClaims = await _claimService.GetClaimsAsync(username);
        return userClaims;
    };
});
```

---

## Events

Hook into the authentication lifecycle for custom behavior.

```csharp
builder.Services.AddBasicAuthGuard(options =>
{
    options.Username = "admin";
    options.Password = "password";
    
    options.Events.OnValidateCredentials = async context =>
    {
        // Custom credential validation
        if (context.Username == "admin" && context.Password == "admin")
        {
            context.ValidationSucceeded();
        }
        else
        {
            context.ValidationFailed("Invalid credentials");
        }
    };
    
    options.Events.OnAuthenticationSucceeded = async context =>
    {
        // Log successful authentication
        Console.WriteLine($"User {context.Username} authenticated successfully");
    };
    
    options.Events.OnAuthenticationFailed = async context =>
    {
        // Log failed authentication
        Console.WriteLine($"Authentication failed for {context.Username}: {context.FailureReason}");
    };
    
    options.Events.OnChallenge = async context =>
    {
        // Customize challenge response
        context.Response.Headers.Append("X-Custom-Header", "value");
    };
    
    options.Events.OnForbidden = async context =>
    {
        // Customize forbidden response
        context.Handled = true;
        context.Response.StatusCode = 403;
        await context.Response.WriteAsync("Access denied");
    };
});
```

### BasicAuthenticationEvents

| Event | Description |
|-------|-------------|
| `OnValidateCredentials` | Validate credentials with custom logic |
| `OnAuthenticationSucceeded` | Called after successful authentication |
| `OnAuthenticationFailed` | Called after failed authentication |
| `OnChallenge` | Customize 401 challenge response |
| `OnForbidden` | Customize 403 forbidden response |

---

## Configuration Options Reference

### BasicAuthenticationOptions

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `Realm` | `string` | `"Protected"` | Realm for WWW-Authenticate |
| `Username` | `string?` | `null` | Single user username |
| `Password` | `string?` | `null` | Single user password (plain) |
| `PasswordHash` | `string?` | `null` | Single user password (hashed) |
| `HashAlgorithm` | `PasswordHashAlgorithm` | `None` | Hash algorithm to use |
| `Users` | `IList<BasicAuthenticationUser>` | `[]` | Configured users |
| `SuppressWwwAuthenticateHeader` | `bool` | `false` | Suppress WWW-Authenticate header |
| `IgnoreAuthenticationIfAllowAnonymous` | `bool` | `true` | Skip auth for [AllowAnonymous] |
| `RateLimiting` | `RateLimitOptions?` | `null` | Rate limiting config |
| `IpWhitelist` | `IpWhitelistOptions?` | `null` | IP whitelist config |
| `AuditLog` | `AuditLogOptions?` | `null` | Audit logging config |
| `ValidateCredentialsAsync` | `Func<...>?` | `null` | Custom validation delegate |
| `GetAdditionalClaimsAsync` | `Func<...>?` | `null` | Additional claims provider |
| `Events` | `BasicAuthenticationEvents` | `new()` | Event handlers |

---

## Defaults

```csharp
public class BasicAuthenticationDefaults
{
    public const string AuthenticationScheme = "BasicAuthentication";
    public const string Realm = "Protected";
    public const string PolicyName = "BasicAuthenticationPolicy";
}
```

---

## Complete Example

```csharp
using AspNetCore.BasicAuthentication.Extensions;
using System.Security.Claims;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddOpenApi();

// Configure comprehensive basic authentication
builder.Services.AddBasicAuthGuard(options =>
{
    options.Realm = "My API";
    options.HashAlgorithm = PasswordHashAlgorithm.BCrypt;
    
    // Add multiple users
    options.AddUser("admin", "adminpass", roles: ["Admin", "User"]);
    options.AddUser("user", "userpass", roles: ["User"]);
    options.AddUserWithSchedule("contractor", "contractorpass",
        new AccessSchedule
        {
            AllowedDays = [DayOfWeek.Monday, DayOfWeek.Tuesday, 
                          DayOfWeek.Wednesday, DayOfWeek.Thursday, 
                          DayOfWeek.Friday],
            AllowedFromHour = 9,
            AllowedToHour = 17
        },
        roles: ["Contractor"]);
    
    // Rate limiting
    options.WithRateLimiting(rate =>
    {
        rate.MaxFailedAttempts = 5;
        rate.LockoutDuration = TimeSpan.FromMinutes(15);
    });
    
    // IP restrictions
    options.WithIpWhitelist(ip =>
    {
        ip.AllowedRanges = ["10.0.0.0/8", "192.168.0.0/16"];
    });
    
    // Audit logging
    options.WithAuditLog(audit =>
    {
        audit.Enabled = true;
        audit.IncludeIpAddress = true;
        audit.IncludeUserAgent = true;
    });
});

var app = builder.Build();

// URL-based authentication
app.AddBasicAuthGuard("/health", "monitor", "monitorpass");
app.UseBasicAuthGuard(auth =>
{
    auth.AddPattern("/metrics", "metrics", "metricspass");
    auth.AddPattern("/api/internal/**", "internal", "internalpass");
});

// Public endpoint
app.MapGet("/", () => "Welcome!");

// Protected endpoints with per-endpoint auth
app.MapGet("/api/users", () => new[] { "user1", "user2" })
   .RequireBasicAuth();

app.MapGet("/api/admin", () => "Admin data")
   .RequireBasicAuth("admin", "adminpass");

// Health check (protected by URL-based auth)
app.MapGet("/health", () => Results.Ok(new { status = "healthy" }));

app.Run();
```

---

## License

MIT License - see [LICENSE](LICENSE) for details.
