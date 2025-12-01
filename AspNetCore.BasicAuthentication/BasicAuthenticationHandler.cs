using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using AspNetCore.BasicAuthentication.RateLimiting;
using AspNetCore.BasicAuthentication.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace AspNetCore.BasicAuthentication;

/// <summary>
/// Authentication handler for Basic authentication
/// </summary>
public class BasicAuthenticationHandler : AuthenticationHandler<BasicAuthenticationOptions>
{
    private readonly IPasswordHasher _passwordHasher;
    private readonly IRateLimiter? _rateLimiter;
    private readonly IAuditLogger _auditLogger;

    /// <summary>
    /// Creates a new instance of the handler
    /// </summary>
    public BasicAuthenticationHandler(
        IOptionsMonitor<BasicAuthenticationOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder,
        IPasswordHasher passwordHasher,
        IRateLimiter? rateLimiter = null,
        IAuditLogger? auditLogger = null)
        : base(options, logger, encoder)
    {
        _passwordHasher = passwordHasher;
        _rateLimiter = rateLimiter;
        _auditLogger = auditLogger ?? NullAuditLogger.Instance;
    }

    /// <inheritdoc />
    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        // Check if AllowAnonymous is present
        if (Options.IgnoreAuthenticationIfAllowAnonymous)
        {
            var endpoint = Context.GetEndpoint();
            if (endpoint?.Metadata.GetMetadata<IAllowAnonymous>() != null)
            {
                return AuthenticateResult.NoResult();
            }
        }

        // Check IP restrictions
        if (Options.IpWhitelist != null)
        {
            var clientIp = Context.Connection.RemoteIpAddress;

            if (!Options.IpWhitelist.IsIpAllowed(clientIp))
            {
                _auditLogger.LogFailure(Context, null, "IP address blocked", Scheme.Name);
                return AuthenticateResult.Fail("IP address not allowed");
            }

            if (Options.IpWhitelist.ShouldBypassAuth(clientIp))
            {
                // Create anonymous principal for bypassed requests
                var bypassIdentity = new ClaimsIdentity(
                    [new Claim(ClaimTypes.Name, "ip-bypass"), new Claim("ip", clientIp?.ToString() ?? "unknown")],
                    Scheme.Name);
                return AuthenticateResult.Success(new AuthenticationTicket(new ClaimsPrincipal(bypassIdentity),
                    Scheme.Name));
            }
        }

        // Check for Authorization header
        if (!Request.Headers.ContainsKey("Authorization"))
        {
            return AuthenticateResult.NoResult();
        }

        // Parse Authorization header
        if (!AuthenticationHeaderValue.TryParse(Request.Headers.Authorization, out var authHeader))
        {
            return AuthenticateResult.Fail("Invalid Authorization header");
        }

        if (!string.Equals(authHeader.Scheme, "Basic", StringComparison.OrdinalIgnoreCase))
        {
            return AuthenticateResult.NoResult();
        }

        if (string.IsNullOrEmpty(authHeader.Parameter))
        {
            return AuthenticateResult.Fail("Missing credentials");
        }

        // Decode credentials
        string username;
        string password;
        try
        {
            var credentialBytes = Convert.FromBase64String(authHeader.Parameter);
            var credentials = Encoding.UTF8.GetString(credentialBytes).Split(':', 2);

            if (credentials.Length != 2)
            {
                return AuthenticateResult.Fail("Invalid credentials format");
            }

            username = credentials[0];
            password = credentials[1];
        }
        catch (FormatException)
        {
            return AuthenticateResult.Fail("Invalid Base64 encoding");
        }

        // Check rate limiting
        if (_rateLimiter != null && Options.RateLimiting != null)
        {
            var rateLimitKey = BuildRateLimitKey(username);
            if (_rateLimiter.IsLockedOut(rateLimitKey))
            {
                var remaining = _rateLimiter.GetRemainingLockoutTime(rateLimitKey);
                _auditLogger.LogFailure(Context, username, "Rate limited", Scheme.Name);

                var failedContext = new AuthenticationFailedContext(
                    Context, Scheme, Options, username, "Too many failed attempts");
                await Options.Events.AuthenticationFailedAsync(failedContext);

                return AuthenticateResult.Fail(
                    Options.RateLimiting.LockoutMessage ??
                    $"Too many failed attempts. Try again in {remaining?.TotalMinutes:F0} minutes.");
            }
        }

        // Validate credentials
        var validationResult = await ValidateCredentialsAsync(username, password);

        if (!validationResult.IsValid)
        {
            // Record failed attempt
            if (_rateLimiter != null && Options.RateLimiting != null)
            {
                var rateLimitKey = BuildRateLimitKey(username);
                _rateLimiter.RecordFailedAttempt(rateLimitKey);
            }

            _auditLogger.LogFailure(Context, username, validationResult.FailureReason ?? "Invalid credentials",
                Scheme.Name);

            var failedContext = new AuthenticationFailedContext(
                Context, Scheme, Options, username, validationResult.FailureReason ?? "Invalid credentials");
            await Options.Events.AuthenticationFailedAsync(failedContext);

            return AuthenticateResult.Fail(validationResult.FailureReason ?? "Invalid credentials");
        }

        // Reset rate limiter on success
        if (_rateLimiter != null && Options.RateLimiting != null)
        {
            var rateLimitKey = BuildRateLimitKey(username);
            _rateLimiter.Reset(rateLimitKey);
        }

        // Build claims
        var claims = new List<Claim>
        {
            new(ClaimTypes.Name, username),
            new(ClaimTypes.NameIdentifier, username),
            new(ClaimTypes.AuthenticationMethod, "Basic")
        };

        // Add user-specific claims
        if (validationResult.User != null)
        {
            foreach (var role in validationResult.User.Roles)
            {
                claims.Add(new Claim(ClaimTypes.Role, role));
            }

            claims.AddRange(validationResult.User.Claims);
        }

        // Get additional claims from delegate
        if (Options.GetAdditionalClaimsAsync != null)
        {
            var additionalClaims = await Options.GetAdditionalClaimsAsync(username, Context);
            claims.AddRange(additionalClaims);
        }

        var identity = new ClaimsIdentity(claims, Scheme.Name);
        var principal = new ClaimsPrincipal(identity);
        var ticket = new AuthenticationTicket(principal, Scheme.Name);

        _auditLogger.LogSuccess(Context, username, Scheme.Name);

        var succeededContext = new AuthenticationSucceededContext(Context, Scheme, Options, username);
        await Options.Events.AuthenticationSucceededAsync(succeededContext);

        return AuthenticateResult.Success(ticket);
    }

    /// <inheritdoc />
    protected override async Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        var challengeContext = new BasicAuthChallengeContext(Context, Scheme, Options, properties);
        await Options.Events.ChallengeAsync(challengeContext);

        if (challengeContext.Handled)
        {
            return;
        }

        Response.StatusCode = StatusCodes.Status401Unauthorized;

        if (!Options.SuppressWwwAuthenticateHeader)
        {
            Response.Headers.WWWAuthenticate = $"""Basic realm="{Options.Realm}", charset="UTF-8" """;
        }
    }

    /// <inheritdoc />
    protected override async Task HandleForbiddenAsync(AuthenticationProperties properties)
    {
        var forbiddenContext = new BasicAuthForbiddenContext(Context, Scheme, Options, properties);
        await Options.Events.ForbiddenAsync(forbiddenContext);

        if (forbiddenContext.Handled)
        {
            return;
        }

        Response.StatusCode = StatusCodes.Status403Forbidden;
    }

    private async Task<ValidationResult> ValidateCredentialsAsync(string username, string password)
    {
        // Check custom validation delegate first
        if (Options.ValidateCredentialsAsync != null)
        {
            var isValid = await Options.ValidateCredentialsAsync(username, password, Context);
            return isValid
                ? ValidationResult.Success()
                : ValidationResult.Failed("Invalid credentials");
        }

        // Check events delegate
        if (Options.Events.OnValidateCredentials != null)
        {
            var context = new ValidateCredentialsContext(Context, Scheme, Options, username, password);
            await Options.Events.ValidateCredentialsAsync(context);

            if (context.Result?.Succeeded == true)
            {
                return ValidationResult.Success();
            }

            return ValidationResult.Failed(context.Result?.Failure?.Message ?? "Invalid credentials");
        }

        // Check configured users
        if (Options.Users.Count > 0)
        {
            var user = Options.Users.FirstOrDefault(u =>
                string.Equals(u.Username, username, StringComparison.Ordinal));

            if (user == null)
            {
                return ValidationResult.Failed("Invalid username");
            }

            if (!user.IsEnabled)
            {
                return ValidationResult.Failed("User account is disabled");
            }

            // Check schedule
            if (user.Schedule != null && !user.Schedule.IsAccessAllowed())
            {
                return ValidationResult.Failed("Access not allowed at this time");
            }

            // Verify password
            if (!string.IsNullOrEmpty(user.PasswordHash))
            {
                if (_passwordHasher.Verify(password, user.PasswordHash, Options.HashAlgorithm))
                {
                    return ValidationResult.Success(user);
                }
            }
            else if (!string.IsNullOrEmpty(user.Password))
            {
                if (string.Equals(user.Password, password, StringComparison.Ordinal))
                {
                    return ValidationResult.Success(user);
                }
            }

            return ValidationResult.Failed("Invalid password");
        }

        // Check single user credentials
        if (!string.IsNullOrEmpty(Options.Username))
        {
            if (!string.Equals(Options.Username, username, StringComparison.Ordinal))
            {
                return ValidationResult.Failed("Invalid username");
            }

            // Check hashed password
            if (!string.IsNullOrEmpty(Options.PasswordHash))
            {
                if (_passwordHasher.Verify(password, Options.PasswordHash, Options.HashAlgorithm))
                {
                    return ValidationResult.Success();
                }
            }
            // Check plain text password
            else if (!string.IsNullOrEmpty(Options.Password))
            {
                if (string.Equals(Options.Password, password, StringComparison.Ordinal))
                {
                    return ValidationResult.Success();
                }
            }

            return ValidationResult.Failed("Invalid password");
        }

        return ValidationResult.Failed("No credentials configured");
    }

    private string BuildRateLimitKey(string username)
    {
        var parts = new List<string>();

        if (Options.RateLimiting?.PerIp == true)
        {
            parts.Add(Context.Connection.RemoteIpAddress?.ToString() ?? "unknown");
        }

        if (Options.RateLimiting?.IncludeUsername == true)
        {
            parts.Add(username);
        }

        return string.Join(":", parts);
    }

    private record ValidationResult(bool IsValid, string? FailureReason = null, BasicAuthenticationUser? User = null)
    {
        public static ValidationResult Success(BasicAuthenticationUser? user = null) => new(true, null, user);
        public static ValidationResult Failed(string reason) => new(false, reason);
    }
}