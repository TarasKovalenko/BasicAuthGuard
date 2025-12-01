using System.Security.Claims;
using Microsoft.AspNetCore.Http;

namespace AspNetCore.BasicAuthentication.Options;

/// <summary>
/// Options for per-endpoint basic authentication configuration
/// </summary>
public class EndpointBasicAuthenticationOptions
{
    /// <summary>
    /// Username for this endpoint
    /// </summary>
    public string? Username { get; set; }

    /// <summary>
    /// Password for this endpoint
    /// </summary>
    public string? Password { get; set; }

    /// <summary>
    /// Realm for WWW-Authenticate header
    /// </summary>
    public string? Realm { get; set; }

    /// <summary>
    /// Custom validation delegate for this endpoint
    /// </summary>
    public Func<string, string, HttpContext, Task<bool>>? ValidateCredentialsAsync { get; set; }

    /// <summary>
    /// Additional claims to add on successful authentication
    /// </summary>
    public IList<Claim> Claims { get; set; } = [];

    /// <summary>
    /// Roles required for this endpoint
    /// </summary>
    public IList<string> Roles { get; set; } = [];
}