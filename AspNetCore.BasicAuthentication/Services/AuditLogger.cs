using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace AspNetCore.BasicAuthentication.Services;

/// <summary>
/// Service for logging authentication events
/// </summary>
public interface IAuditLogger
{
    /// <summary>
    /// Logs a successful authentication
    /// </summary>
    void LogSuccess(HttpContext context, string username, string scheme);

    /// <summary>
    /// Logs a failed authentication
    /// </summary>
    void LogFailure(HttpContext context, string? username, string reason, string scheme);
}

/// <summary>
/// Default implementation of audit logger
/// </summary>
public class AuditLogger : IAuditLogger
{
    private readonly ILogger<AuditLogger> _logger;
    private readonly AuditLogOptions _options;

    private const string DefaultSuccessTemplate =
        "[AspNetCore.BasicAuthentication] Authentication succeeded for user '{Username}' from {IpAddress} on {Path}";

    private const string DefaultFailureTemplate =
        "[AspNetCore.BasicAuthentication] Authentication failed for user '{Username}' from {IpAddress} on {Path}. Reason: {Reason}";

    /// <summary>
    /// Creates a new instance
    /// </summary>
    public AuditLogger(ILogger<AuditLogger> logger, AuditLogOptions options)
    {
        _logger = logger;
        _options = options;
    }

    /// <inheritdoc />
    public void LogSuccess(HttpContext context, string username, string scheme)
    {
        if (!_options.Enabled)
        {
            return;
        }

        var ipAddress = _options.IncludeIpAddress
            ? context.Connection.RemoteIpAddress?.ToString() ?? "unknown"
            : "redacted";

        var userAgent = _options.IncludeUserAgent
            ? context.Request.Headers.UserAgent.ToString()
            : null;

        var path = _options.IncludeRequestPath
            ? context.Request.Path.ToString()
            : "redacted";

        var template = _options.SuccessMessageTemplate ?? DefaultSuccessTemplate;

        _logger.Log(
            _options.SuccessLogLevel,
            template,
            username,
            ipAddress,
            path,
            scheme,
            userAgent ?? "N/A");
    }

    /// <inheritdoc />
    public void LogFailure(HttpContext context, string? username, string reason, string scheme)
    {
        if (!_options.Enabled)
        {
            return;
        }

        var displayUsername = _options.IncludeUsernameOnFailure
            ? username ?? "anonymous"
            : "redacted";

        var ipAddress = _options.IncludeIpAddress
            ? context.Connection.RemoteIpAddress?.ToString() ?? "unknown"
            : "redacted";

        var userAgent = _options.IncludeUserAgent
            ? context.Request.Headers.UserAgent.ToString()
            : null;

        var path = _options.IncludeRequestPath
            ? context.Request.Path.ToString()
            : "redacted";

        var template = _options.FailureMessageTemplate ?? DefaultFailureTemplate;

        _logger.Log(
            _options.FailureLogLevel,
            template,
            displayUsername,
            ipAddress,
            path,
            reason,
            scheme,
            userAgent ?? "N/A");
    }
}

/// <summary>
/// Null implementation for when audit logging is disabled
/// </summary>
public class NullAuditLogger : IAuditLogger
{
    /// <summary>
    /// Singleton instance
    /// </summary>
    public static readonly NullAuditLogger Instance = new();

    private NullAuditLogger() { }

    /// <inheritdoc />
    public void LogSuccess(HttpContext context, string username, string scheme) { }

    /// <inheritdoc />
    public void LogFailure(HttpContext context, string? username, string reason, string scheme) { }
}