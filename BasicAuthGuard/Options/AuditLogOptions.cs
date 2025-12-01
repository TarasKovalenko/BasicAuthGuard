using Microsoft.Extensions.Logging;

namespace AspNetCore.BasicAuthentication.Options;

/// <summary>
/// Configuration options for audit logging
/// </summary>
public class AuditLogOptions
{
    /// <summary>
    /// Whether audit logging is enabled
    /// </summary>
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// Log level for successful authentications
    /// </summary>
    public LogLevel SuccessLogLevel { get; set; } = LogLevel.Information;

    /// <summary>
    /// Log level for failed authentications
    /// </summary>
    public LogLevel FailureLogLevel { get; set; } = LogLevel.Warning;

    /// <summary>
    /// Whether to include the client IP address in log messages
    /// </summary>
    public bool IncludeIpAddress { get; set; } = true;

    /// <summary>
    /// Whether to include the User-Agent header in log messages
    /// </summary>
    public bool IncludeUserAgent { get; set; } = false;

    /// <summary>
    /// Whether to include the request path in log messages
    /// </summary>
    public bool IncludeRequestPath { get; set; } = true;

    /// <summary>
    /// Whether to log the username on failed attempts (disable to prevent username enumeration in logs)
    /// </summary>
    public bool IncludeUsernameOnFailure { get; set; } = true;

    /// <summary>
    /// Custom log message template for successful authentication.
    /// Available placeholders: {Username}, {IpAddress}, {UserAgent}, {Path}, {Scheme}
    /// </summary>
    public string? SuccessMessageTemplate { get; set; }

    /// <summary>
    /// Custom log message template for failed authentication.
    /// Available placeholders: {Username}, {IpAddress}, {UserAgent}, {Path}, {Scheme}, {Reason}
    /// </summary>
    public string? FailureMessageTemplate { get; set; }
}