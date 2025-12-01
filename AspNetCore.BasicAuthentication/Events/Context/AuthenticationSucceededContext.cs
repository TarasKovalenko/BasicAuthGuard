using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace AspNetCore.BasicAuthentication.Events.Context;

/// <summary>
/// Context for successful authentication
/// </summary>
public class AuthenticationSucceededContext : ResultContext<BasicAuthenticationOptions>
{
    /// <summary>
    /// The authenticated username
    /// </summary>
    public string Username { get; }

    /// <summary>
    /// Creates a new instance
    /// </summary>
    public AuthenticationSucceededContext(
        HttpContext context,
        AuthenticationScheme scheme,
        BasicAuthenticationOptions options,
        string username)
        : base(context, scheme, options)
    {
        Username = username;
    }
}