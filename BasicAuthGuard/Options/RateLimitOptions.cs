namespace AspNetCore.BasicAuthentication.Options;

/// <summary>
/// Configuration options for rate limiting failed authentication attempts
/// </summary>
public class RateLimitOptions
{
    /// <summary>
    /// Maximum number of failed attempts before lockout
    /// </summary>
    public int MaxFailedAttempts { get; set; } = 5;

    /// <summary>
    /// Duration of the lockout period
    /// </summary>
    public TimeSpan LockoutDuration { get; set; } = TimeSpan.FromMinutes(15);

    /// <summary>
    /// Time window for counting failed attempts
    /// </summary>
    public TimeSpan AttemptWindow { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Whether to track attempts per IP address (true) or globally per username (false)
    /// </summary>
    public bool PerIp { get; set; } = true;

    /// <summary>
    /// Whether to include the username in the lockout key (prevents username enumeration attacks when false)
    /// </summary>
    public bool IncludeUsername { get; set; } = true;

    /// <summary>
    /// Custom response message when rate limited
    /// </summary>
    public string? LockoutMessage { get; set; }
}