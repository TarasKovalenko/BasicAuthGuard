using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace AspNetCore.BasicAuthentication.Events.Context;

/// <summary>
/// Context for forbidden response
/// </summary>
public class BasicAuthForbiddenContext : PropertiesContext<BasicAuthenticationOptions>
{
    /// <summary>
    /// Whether the forbidden response has been handled
    /// </summary>
    public bool Handled { get; private set; }

    /// <summary>
    /// Creates a new instance
    /// </summary>
    public BasicAuthForbiddenContext(
        HttpContext context,
        AuthenticationScheme scheme,
        BasicAuthenticationOptions options,
        AuthenticationProperties? properties)
        : base(context, scheme, options, properties)
    {
    }

    /// <summary>
    /// Marks the forbidden as handled
    /// </summary>
    public void HandleResponse() => Handled = true;
}