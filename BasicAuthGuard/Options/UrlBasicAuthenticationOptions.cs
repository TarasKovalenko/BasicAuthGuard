using System.Security.Claims;
using Microsoft.AspNetCore.Http;

namespace AspNetCore.BasicAuthentication.Options;

/// <summary>
/// Options for URL-based basic authentication configuration
/// </summary>
public class UrlBasicAuthenticationOptions
{
    /// <summary>
    /// URL pattern to match (supports wildcards like /api/*)
    /// </summary>
    public string UrlPattern { get; set; } = string.Empty;

    /// <summary>
    /// Username for this URL pattern
    /// </summary>
    public string? Username { get; set; }

    /// <summary>
    /// Password for this URL pattern
    /// </summary>
    public string? Password { get; set; }

    /// <summary>
    /// Realm for WWW-Authenticate header
    /// </summary>
    public string? Realm { get; set; }

    /// <summary>
    /// Custom validation delegate for this URL pattern
    /// </summary>
    public Func<string, string, HttpContext, Task<bool>>? ValidateCredentialsAsync { get; set; }

    /// <summary>
    /// Additional claims to add on successful authentication
    /// </summary>
    public IList<Claim> Claims { get; set; } = [];

    /// <summary>
    /// Roles to assign on successful authentication
    /// </summary>
    public IList<string> Roles { get; set; } = [];

    /// <summary>
    /// Whether to use case-insensitive URL matching (default: true)
    /// </summary>
    public bool CaseInsensitiveUrlMatching { get; set; } = true;
}
