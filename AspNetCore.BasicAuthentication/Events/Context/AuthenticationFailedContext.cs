using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace AspNetCore.BasicAuthentication.Events.Context;

/// <summary>
/// Context for authentication failure
/// </summary>
public class AuthenticationFailedContext : ResultContext<BasicAuthenticationOptions>
{
    /// <summary>
    /// The username that failed authentication (if provided)
    /// </summary>
    public string? Username { get; }

    /// <summary>
    /// The exception that caused the failure (if any)
    /// </summary>
    public Exception? Exception { get; }

    /// <summary>
    /// The failure reason
    /// </summary>
    public string FailureReason { get; }

    /// <summary>
    /// Creates a new instance
    /// </summary>
    public AuthenticationFailedContext(
        HttpContext context,
        AuthenticationScheme scheme,
        BasicAuthenticationOptions options,
        string? username,
        string failureReason,
        Exception? exception = null)
        : base(context, scheme, options)
    {
        Username = username;
        FailureReason = failureReason;
        Exception = exception;
    }
}