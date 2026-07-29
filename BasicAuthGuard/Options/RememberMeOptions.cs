using Microsoft.AspNetCore.Http;

namespace AspNetCore.BasicAuthentication.Options;

/// <summary>
/// Configuration for the persistent "remember me" cookie issued after a successful
/// Basic authentication.
/// </summary>
public class RememberMeOptions
{
    /// <summary>
    /// The longest lifetime a remember-me cookie may be configured with
    /// </summary>
    public static readonly TimeSpan MaxDuration = TimeSpan.FromDays(365);

    private TimeSpan _duration = TimeSpan.FromDays(14);

    /// <summary>
    /// Name of the cookie holding the encrypted authentication ticket
    /// </summary>
    public string CookieName { get; set; } = ".BasicAuthGuard.Remember";

    /// <summary>
    /// How long the cookie stays valid. Must be greater than zero and at most 365 days.
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException">
    /// Thrown when the value is not greater than zero or exceeds <see cref="MaxDuration"/>
    /// </exception>
    public TimeSpan Duration
    {
        get => _duration;
        set
        {
            if (value <= TimeSpan.Zero || value > MaxDuration)
            {
                throw new ArgumentOutOfRangeException(
                    nameof(value),
                    value,
                    "Duration must be greater than zero and at most 365 days.");
            }

            _duration = value;
        }
    }

    /// <summary>
    /// If true, the cookie is re-issued with a fresh lifetime on every request it authenticates
    /// </summary>
    public bool SlidingExpiration { get; set; }

    /// <summary>
    /// Controls whether the cookie is marked Secure. Defaults to <see cref="CookieSecurePolicy.Always"/>.
    /// </summary>
    public CookieSecurePolicy SecurePolicy { get; set; } = CookieSecurePolicy.Always;

    /// <summary>
    /// SameSite attribute of the cookie
    /// </summary>
    public SameSiteMode SameSite { get; set; } = SameSiteMode.Lax;

    /// <summary>
    /// Path the cookie is scoped to
    /// </summary>
    public string Path { get; set; } = "/";

    /// <summary>
    /// Optional domain the cookie is scoped to
    /// </summary>
    public string? Domain { get; set; }
}
