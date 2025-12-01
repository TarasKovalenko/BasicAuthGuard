using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
using System.Text.RegularExpressions;
using AspNetCore.BasicAuthentication.Options;
using Microsoft.AspNetCore.Http;

namespace AspNetCore.BasicAuthentication.Middleware;

/// <summary>
/// Middleware for URL-based basic authentication
/// </summary>
public class UrlBasicAuthenticationMiddleware
{
    private readonly RequestDelegate _next;
    private readonly List<UrlBasicAuthenticationEntry> _entries;

    public UrlBasicAuthenticationMiddleware(RequestDelegate next, List<UrlBasicAuthenticationEntry> entries)
    {
        _next = next;
        _entries = entries;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var path = context.Request.Path.Value ?? string.Empty;

        // Find matching entry
        var matchingEntry = _entries.FirstOrDefault(e => e.Matches(path));

        if (matchingEntry == null)
        {
            // No matching pattern, continue to next middleware
            await _next(context);
            return;
        }

        // Check for Authorization header
        if (!context.Request.Headers.TryGetValue("Authorization", out var authHeader))
        {
            await CreateUnauthorizedResponse(context, matchingEntry.Options);
            return;
        }

        // Parse Authorization header
        if (!AuthenticationHeaderValue.TryParse(authHeader, out var parsedHeader))
        {
            await CreateUnauthorizedResponse(context, matchingEntry.Options);
            return;
        }

        if (!string.Equals(parsedHeader.Scheme, "Basic", StringComparison.OrdinalIgnoreCase))
        {
            await CreateUnauthorizedResponse(context, matchingEntry.Options);
            return;
        }

        if (string.IsNullOrEmpty(parsedHeader.Parameter))
        {
            await CreateUnauthorizedResponse(context, matchingEntry.Options);
            return;
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
                await CreateUnauthorizedResponse(context, matchingEntry.Options);
                return;
            }

            username = credentials[0];
            password = credentials[1];
        }
        catch (FormatException)
        {
            await CreateUnauthorizedResponse(context, matchingEntry.Options);
            return;
        }

        // Validate credentials
        var options = matchingEntry.Options;
        bool isValid;

        if (options.ValidateCredentialsAsync != null)
        {
            isValid = await options.ValidateCredentialsAsync(username, password, context);
        }
        else if (options is { Username: not null, Password: not null })
        {
            isValid = string.Equals(options.Username, username, StringComparison.Ordinal) &&
                      string.Equals(options.Password, password, StringComparison.Ordinal);
        }
        else
        {
            // No validation configured, deny access
            await CreateUnauthorizedResponse(context, options);
            return;
        }

        if (!isValid)
        {
            await CreateUnauthorizedResponse(context, options);
            return;
        }

        // Build claims and set user
        var claims = new List<Claim>
        {
            new(ClaimTypes.Name, username),
            new(ClaimTypes.NameIdentifier, username),
            new(ClaimTypes.AuthenticationMethod, "Basic")
        };

        foreach (var role in options.Roles)
        {
            claims.Add(new Claim(ClaimTypes.Role, role));
        }

        claims.AddRange(options.Claims);

        var identity = new ClaimsIdentity(claims, "BasicAuthUrl");
        context.User = new ClaimsPrincipal(identity);

        await _next(context);
    }

    private static Task CreateUnauthorizedResponse(HttpContext context, UrlBasicAuthenticationOptions options)
    {
        var realm = options.Realm ?? BasicAuthenticationDefaults.Realm;
        context.Response.Headers.WWWAuthenticate = $"""Basic realm="{realm}", charset="UTF-8" """;
        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
        return Task.CompletedTask;
    }
}

/// <summary>
/// Entry for URL-based authentication matching
/// </summary>
public class UrlBasicAuthenticationEntry
{
    private readonly Regex? _regex;
    private readonly string _exactPath;
    private readonly bool _isWildcard;
    private readonly bool _caseInsensitive;

    public UrlBasicAuthenticationOptions Options { get; }

    public UrlBasicAuthenticationEntry(UrlBasicAuthenticationOptions options)
    {
        Options = options;
        _caseInsensitive = options.CaseInsensitiveUrlMatching;
        _exactPath = options.UrlPattern;

        // Check if pattern contains wildcards
        if (options.UrlPattern.Contains('*') || options.UrlPattern.Contains('?'))
        {
            _isWildcard = true;
            // Convert glob pattern to regex
            var regexPattern = "^" + Regex.Escape(options.UrlPattern)
                .Replace("\\*\\*", ".*") // ** matches any path including /
                .Replace("\\*", "[^/]*") // * matches any segment except /
                .Replace("\\?", "[^/]") + "$"; // ? matches single char except /

            var regexOptions = RegexOptions.Compiled;
            if (_caseInsensitive)
            {
                regexOptions |= RegexOptions.IgnoreCase;
            }

            _regex = new Regex(regexPattern, regexOptions);
        }
        else
        {
            _isWildcard = false;
        }
    }

    public bool Matches(string path)
    {
        if (_isWildcard && _regex != null)
        {
            return _regex.IsMatch(path);
        }

        // Exact match or prefix match
        var comparison = _caseInsensitive
            ? StringComparison.OrdinalIgnoreCase
            : StringComparison.Ordinal;

        return string.Equals(path, _exactPath, comparison) ||
               path.StartsWith(_exactPath.TrimEnd('/') + "/", comparison);
    }
}