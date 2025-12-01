using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace AspNetCore.BasicAuthentication.Events.Context;

/// <summary>
/// Context for authentication challenge
/// </summary>
public class BasicAuthChallengeContext : PropertiesContext<BasicAuthenticationOptions>
{
    /// <summary>
    /// Whether the challenge has been handled
    /// </summary>
    public bool Handled { get; private set; }

    /// <summary>
    /// Creates a new instance
    /// </summary>
    public BasicAuthChallengeContext(
        HttpContext context,
        AuthenticationScheme scheme,
        BasicAuthenticationOptions options,
        AuthenticationProperties? properties)
        : base(context, scheme, options, properties)
    {
    }

    /// <summary>
    /// Marks the challenge as handled
    /// </summary>
    public void HandleResponse() => Handled = true;
}