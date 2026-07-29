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
    /// the supplied lifetime
    /// </summary>
    string Protect(AuthenticationTicket ticket, TimeSpan lifetime);

    /// <summary>
    /// Decrypts a cookie value back into a ticket. Returns null when the value is
    /// malformed, tampered with, expired, or protected by a different keyring.
    /// </summary>
    AuthenticationTicket? Unprotect(string value);
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

    /// <summary>
    /// Creates a new instance
    /// </summary>
    public RememberMeTicketProtector(IDataProtectionProvider provider)
    {
        _protector = provider.CreateProtector(ProtectorPurpose).ToTimeLimitedDataProtector();
    }

    /// <inheritdoc />
    public string Protect(AuthenticationTicket ticket, TimeSpan lifetime)
    {
        var payload = TicketSerializer.Default.Serialize(ticket);
        var protectedBytes = _protector.Protect(payload, DateTimeOffset.UtcNow.Add(lifetime));
        return WebEncoders.Base64UrlEncode(protectedBytes);
    }

    /// <inheritdoc />
    public AuthenticationTicket? Unprotect(string value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return null;
        }

        try
        {
            var protectedBytes = WebEncoders.Base64UrlDecode(value);
            var payload = _protector.Unprotect(protectedBytes);
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
