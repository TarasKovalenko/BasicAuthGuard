using System.Collections.Concurrent;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.WebUtilities;

namespace AspNetCore.BasicAuthentication.Services;

/// <summary>
/// Protects and unprotects the authentication ticket stored in the remember-me cookie
/// </summary>
public interface IRememberMeTicketProtector
{
    /// <summary>
    /// Serializes and encrypts a ticket into a cookie-safe string that expires after
    /// the supplied lifetime, scoped to <paramref name="schemeName"/> so a cookie
    /// minted for one BasicAuthGuard scheme cannot be unprotected under another.
    /// </summary>
    string Protect(AuthenticationTicket ticket, TimeSpan lifetime, string schemeName);

    /// <summary>
    /// Decrypts a cookie value that was protected with <paramref name="schemeName"/> back
    /// into a ticket. Returns null when the value is malformed, tampered with, expired,
    /// protected by a different keyring, or was minted for a different scheme.
    /// </summary>
    AuthenticationTicket? Unprotect(string value, string schemeName);
}

/// <summary>
/// Data Protection based implementation of <see cref="IRememberMeTicketProtector"/>
/// </summary>
public sealed class RememberMeTicketProtector : IRememberMeTicketProtector
{
    /// <summary>
    /// Data Protection purpose string. Changing it invalidates every issued cookie.
    /// </summary>
    public const string ProtectorPurpose = "BasicAuthGuard.RememberMe.v1";

    private readonly ITimeLimitedDataProtector _protector;

    // Per-scheme sub-protectors, derived by adding the scheme name as an additional
    // Data Protection purpose (the same pattern CookieAuthenticationHandler uses). This
    // is what stops a cookie minted by one BasicAuthGuard scheme from unprotecting
    // successfully under another scheme sharing the same protector instance.
    private readonly ConcurrentDictionary<string, ITimeLimitedDataProtector> _schemeProtectors =
        new(StringComparer.Ordinal);

    /// <summary>
    /// Creates a new instance
    /// </summary>
    public RememberMeTicketProtector(IDataProtectionProvider provider)
    {
        _protector = provider.CreateProtector(ProtectorPurpose).ToTimeLimitedDataProtector();
    }

    /// <inheritdoc />
    public string Protect(AuthenticationTicket ticket, TimeSpan lifetime, string schemeName) =>
        ProtectCore(GetSchemeProtector(schemeName), ticket, lifetime);

    /// <inheritdoc />
    public AuthenticationTicket? Unprotect(string value, string schemeName) =>
        UnprotectCore(GetSchemeProtector(schemeName), value);

    private ITimeLimitedDataProtector GetSchemeProtector(string schemeName)
    {
        if (string.IsNullOrEmpty(schemeName))
        {
            throw new ArgumentException("Scheme name must not be null or empty.", nameof(schemeName));
        }

        return _schemeProtectors.GetOrAdd(
            schemeName,
            static (name, protector) => ((IDataProtector)protector).CreateProtector(name).ToTimeLimitedDataProtector(),
            _protector);
    }

    private static string ProtectCore(ITimeLimitedDataProtector protector, AuthenticationTicket ticket, TimeSpan lifetime)
    {
        var payload = TicketSerializer.Default.Serialize(ticket);
        var protectedBytes = protector.Protect(payload, DateTimeOffset.UtcNow.Add(lifetime));
        return WebEncoders.Base64UrlEncode(protectedBytes);
    }

    private static AuthenticationTicket? UnprotectCore(ITimeLimitedDataProtector protector, string value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return null;
        }

        try
        {
            var protectedBytes = WebEncoders.Base64UrlDecode(value);
            var payload = protector.Unprotect(protectedBytes);
            return TicketSerializer.Default.Deserialize(payload);
        }
        catch (CryptographicException)
        {
            return null;
        }
        catch (FormatException)
        {
            return null;
        }
        catch (ArgumentException)
        {
            return null;
        }
    }
}
