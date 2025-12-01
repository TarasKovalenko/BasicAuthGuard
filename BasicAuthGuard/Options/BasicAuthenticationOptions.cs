using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace AspNetCore.BasicAuthentication.Options;

/// <summary>
/// Configuration options for BasicAuthentication
/// </summary>
public class BasicAuthenticationOptions : AuthenticationSchemeOptions
{
    /// <summary>
    /// The realm value for the WWW-Authenticate header
    /// </summary>
    public string Realm { get; set; } = BasicAuthenticationDefaults.Realm;

    /// <summary>
    /// Single user username (for simple scenarios)
    /// </summary>
    public string? Username { get; set; }

    /// <summary>
    /// Single user password in plain text
    /// </summary>
    public string? Password { get; set; }

    /// <summary>
    /// Single user password hash
    /// </summary>
    public string? PasswordHash { get; set; }

    /// <summary>
    /// Hash algorithm used for password verification
    /// </summary>
    public PasswordHashAlgorithm HashAlgorithm { get; set; } = PasswordHashAlgorithm.None;

    /// <summary>
    /// List of configured users (for multi-user scenarios)
    /// </summary>
    public IList<BasicAuthenticationUser> Users { get; } = [];

    /// <summary>
    /// If true, suppresses the WWW-Authenticate header on 401 responses
    /// </summary>
    public bool SuppressWwwAuthenticateHeader { get; set; } = false;

    /// <summary>
    /// If true, skips authentication if [AllowAnonymous] is present
    /// </summary>
    public bool IgnoreAuthenticationIfAllowAnonymous { get; set; } = true;

    /// <summary>
    /// Rate limiting configuration
    /// </summary>
    public RateLimitOptions? RateLimiting { get; set; }

    /// <summary>
    /// IP whitelist/blacklist configuration
    /// </summary>
    public IpWhitelistOptions? IpWhitelist { get; set; }

    /// <summary>
    /// Audit logging configuration
    /// </summary>
    public AuditLogOptions? AuditLog { get; set; }

    /// <summary>
    /// Custom credential validation delegate
    /// </summary>
    public Func<string, string, HttpContext, Task<bool>>? ValidateCredentialsAsync { get; set; }

    /// <summary>
    /// Custom claims provider delegate - called after successful authentication
    /// </summary>
    public Func<string, HttpContext, Task<IEnumerable<Claim>>>? GetAdditionalClaimsAsync { get; set; }

    /// <summary>
    /// Events for handling authentication lifecycle
    /// </summary>
    public new BasicAuthenticationEvents Events
    {
        get => (BasicAuthenticationEvents)base.Events!;
        set => base.Events = value;
    }

    /// <summary>
    /// Creates a new instance of BasicAuthGuardOptions
    /// </summary>
    public BasicAuthenticationOptions()
    {
        Events = new BasicAuthenticationEvents();
    }

    /// <summary>
    /// Adds a user with the specified credentials
    /// </summary>
    public BasicAuthenticationOptions AddUser(
        string username,
        string password,
        IEnumerable<string>? roles = null,
        IEnumerable<Claim>? claims = null)
    {
        Users.Add(new BasicAuthenticationUser
        {
            Username = username,
            Password = password,
            Roles = roles?.ToList() ?? [],
            Claims = claims?.ToList() ?? []
        });
        return this;
    }

    /// <summary>
    /// Adds a user with a hashed password
    /// </summary>
    public BasicAuthenticationOptions AddUserWithHash(
        string username,
        string passwordHash,
        PasswordHashAlgorithm algorithm,
        IEnumerable<string>? roles = null,
        IEnumerable<Claim>? claims = null)
    {
        Users.Add(new BasicAuthenticationUser
        {
            Username = username,
            PasswordHash = passwordHash,
            Roles = roles?.ToList() ?? [],
            Claims = claims?.ToList() ?? []
        });
        HashAlgorithm = algorithm;
        return this;
    }

    /// <summary>
    /// Adds a user with schedule restrictions
    /// </summary>
    public BasicAuthenticationOptions AddUserWithSchedule(
        string username,
        string password,
        AccessSchedule schedule,
        IEnumerable<string>? roles = null)
    {
        Users.Add(new BasicAuthenticationUser
        {
            Username = username,
            Password = password,
            Schedule = schedule,
            Roles = roles?.ToList() ?? []
        });
        return this;
    }

    /// <summary>
    /// Configures rate limiting
    /// </summary>
    public BasicAuthenticationOptions WithRateLimiting(Action<RateLimitOptions> configure)
    {
        RateLimiting ??= new RateLimitOptions();
        configure(RateLimiting);
        return this;
    }

    /// <summary>
    /// Configures IP whitelisting
    /// </summary>
    public BasicAuthenticationOptions WithIpWhitelist(Action<IpWhitelistOptions> configure)
    {
        IpWhitelist ??= new IpWhitelistOptions();
        configure(IpWhitelist);
        return this;
    }

    /// <summary>
    /// Configures audit logging
    /// </summary>
    public BasicAuthenticationOptions WithAuditLog(Action<AuditLogOptions> configure)
    {
        AuditLog ??= new AuditLogOptions();
        configure(AuditLog);
        return this;
    }
}