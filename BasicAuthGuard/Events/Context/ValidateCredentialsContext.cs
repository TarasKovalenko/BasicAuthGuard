using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace AspNetCore.BasicAuthentication.Events.Context;

/// <summary>
/// Context for credential validation
/// </summary>
public class ValidateCredentialsContext : ResultContext<BasicAuthenticationOptions>
{
    /// <summary>
    /// The username from the request
    /// </summary>
    public string Username { get; }

    /// <summary>
    /// The password from the request
    /// </summary>
    public string Password { get; }

    /// <summary>
    /// Creates a new instance
    /// </summary>
    public ValidateCredentialsContext(
        HttpContext context,
        AuthenticationScheme scheme,
        BasicAuthenticationOptions options,
        string username,
        string password)
        : base(context, scheme, options)
    {
        Username = username;
        Password = password;
    }

    /// <summary>
    /// Marks validation as successful with the given claims
    /// </summary>
    public void ValidationSucceeded(IEnumerable<Claim>? claims = null)
    {
        var claimsList = new List<Claim>
        {
            new(ClaimTypes.Name, Username),
            new(ClaimTypes.NameIdentifier, Username)
        };

        if (claims != null)
        {
            claimsList.AddRange(claims);
        }

        var identity = new ClaimsIdentity(claimsList, Scheme.Name);
        Principal = new ClaimsPrincipal(identity);
        Success();
    }

    /// <summary>
    /// Marks validation as failed
    /// </summary>
    public void ValidationFailed(string? failureMessage = null)
    {
        Fail(failureMessage ?? "Invalid credentials");
    }
}