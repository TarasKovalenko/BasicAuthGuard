using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;

namespace AspNetCore.BasicAuthentication.Extensions;

/// <summary>
/// Extension methods for adding BasicAuthGuard to endpoints
/// </summary>
public static class EndpointExtensions
{
    /// <summary>
    /// Requires BasicAuthGuard authentication for the endpoint using the default scheme
    /// </summary>
    /// <typeparam name="TBuilder">The endpoint builder type</typeparam>
    /// <param name="builder">The endpoint builder</param>
    /// <returns>The endpoint builder</returns>
    public static TBuilder RequireBasicAuth<TBuilder>(this TBuilder builder)
        where TBuilder : IEndpointConventionBuilder
    {
        return builder.RequireAuthorization(BasicAuthenticationDefaults.PolicyName);
    }

    /// <summary>
    /// Requires BasicAuthGuard authentication for the endpoint with specific credentials
    /// </summary>
    /// <typeparam name="TBuilder">The endpoint builder type</typeparam>
    /// <param name="builder">The endpoint builder</param>
    /// <param name="username">The required username</param>
    /// <param name="password">The required password</param>
    /// <param name="realm">Optional realm name</param>
    /// <returns>The endpoint builder</returns>
    public static TBuilder RequireBasicAuth<TBuilder>(
        this TBuilder builder,
        string username,
        string password,
        string? realm = null)
        where TBuilder : IEndpointConventionBuilder
    {
        var options = new EndpointBasicAuthenticationOptions
        {
            Username = username,
            Password = password,
            Realm = realm
        };

        return builder.AddEndpointFilter(new BasicAuthEndpointFilter(options));
    }

    /// <summary>
    /// Requires BasicAuthGuard authentication for the endpoint with custom options
    /// </summary>
    /// <typeparam name="TBuilder">The endpoint builder type</typeparam>
    /// <param name="builder">The endpoint builder</param>
    /// <param name="configure">Configuration delegate</param>
    /// <returns>The endpoint builder</returns>
    public static TBuilder RequireBasicAuth<TBuilder>(
        this TBuilder builder,
        Action<EndpointBasicAuthenticationOptions> configure)
        where TBuilder : IEndpointConventionBuilder
    {
        var options = new EndpointBasicAuthenticationOptions();
        configure(options);

        return builder.AddEndpointFilter(new BasicAuthEndpointFilter(options));
    }
}

/// <summary>
/// Endpoint filter for per-endpoint basic authentication
/// </summary>
internal class BasicAuthEndpointFilter : IEndpointFilter
{
    private readonly EndpointBasicAuthenticationOptions _options;

    public BasicAuthEndpointFilter(EndpointBasicAuthenticationOptions options)
    {
        _options = options;
    }

    public async ValueTask<object?> InvokeAsync(
        EndpointFilterInvocationContext context,
        EndpointFilterDelegate next)
    {
        var httpContext = context.HttpContext;

        // Check for Authorization header
        if (!httpContext.Request.Headers.TryGetValue("Authorization", out var authHeader))
        {
            return CreateUnauthorizedResponse(httpContext);
        }

        // Parse Authorization header
        if (!AuthenticationHeaderValue.TryParse(authHeader, out var parsedHeader))
        {
            return CreateUnauthorizedResponse(httpContext);
        }

        if (!string.Equals(parsedHeader.Scheme, "Basic", StringComparison.OrdinalIgnoreCase))
        {
            return CreateUnauthorizedResponse(httpContext);
        }

        if (string.IsNullOrEmpty(parsedHeader.Parameter))
        {
            return CreateUnauthorizedResponse(httpContext);
        }

        // Decode credentials
        string username;
        string password;
        try
        {
            var credentialBytes = Convert.FromBase64String(parsedHeader.Parameter);
            var credentials = Encoding.UTF8.GetString(credentialBytes).Split(':', 2);

            if (credentials.Length != 2)
            {
                return CreateUnauthorizedResponse(httpContext);
            }

            username = credentials[0];
            password = credentials[1];
        }
        catch (FormatException)
        {
            return CreateUnauthorizedResponse(httpContext);
        }

        // Validate credentials
        bool isValid;

        if (_options.ValidateCredentialsAsync != null)
        {
            isValid = await _options.ValidateCredentialsAsync(username, password, httpContext);
        }
        else if (_options.Username != null && _options.Password != null)
        {
            isValid = string.Equals(_options.Username, username, StringComparison.Ordinal) &&
                      string.Equals(_options.Password, password, StringComparison.Ordinal);
        }
        else
        {
            // No validation configured, deny access
            return CreateUnauthorizedResponse(httpContext);
        }

        if (!isValid)
        {
            return CreateUnauthorizedResponse(httpContext);
        }

        // Build claims and set user
        var claims = new List<Claim>
        {
            new(ClaimTypes.Name, username),
            new(ClaimTypes.NameIdentifier, username),
            new(ClaimTypes.AuthenticationMethod, "Basic")
        };

        foreach (var role in _options.Roles)
        {
            claims.Add(new Claim(ClaimTypes.Role, role));
        }

        claims.AddRange(_options.Claims);

        var identity = new ClaimsIdentity(claims, "BasicAuthEndpoint");
        httpContext.User = new ClaimsPrincipal(identity);

        return await next(context);
    }

    private IResult CreateUnauthorizedResponse(HttpContext context)
    {
        var realm = _options.Realm ?? BasicAuthenticationDefaults.Realm;
        context.Response.Headers.WWWAuthenticate = $"""Basic realm="{realm}", charset="UTF-8" """;
        return Results.Unauthorized();
    }
}