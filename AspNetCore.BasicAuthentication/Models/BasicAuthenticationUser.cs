using System.Security.Claims;

namespace AspNetCore.BasicAuthentication.Models;

/// <summary>
/// Represents a user for basic authentication
/// </summary>
public class BasicAuthenticationUser
{
    /// <summary>
    /// Username for authentication
    /// </summary>
    public required string Username { get; set; }

    /// <summary>
    /// Plain text password (use PasswordHash for better security)
    /// </summary>
    public string? Password { get; set; }

    /// <summary>
    /// Hashed password
    /// </summary>
    public string? PasswordHash { get; set; }

    /// <summary>
    /// Roles assigned to this user
    /// </summary>
    public IReadOnlyList<string> Roles { get; set; } = [];

    /// <summary>
    /// Additional claims for this user
    /// </summary>
    public IReadOnlyList<Claim> Claims { get; set; } = [];

    /// <summary>
    /// Whether this user account is enabled
    /// </summary>
    public bool IsEnabled { get; set; } = true;

    /// <summary>
    /// Optional access schedule restrictions
    /// </summary>
    public AccessSchedule? Schedule { get; set; }
}

/// <summary>
/// Defines time-based access restrictions
/// </summary>
public class AccessSchedule
{
    /// <summary>
    /// Days of the week when access is allowed. If empty, all days are allowed.
    /// </summary>
    public IReadOnlyList<DayOfWeek> AllowedDays { get; set; } = [];

    /// <summary>
    /// Start hour (0-23) when access is allowed
    /// </summary>
    public int? AllowedFromHour { get; set; }

    /// <summary>
    /// End hour (0-23) when access is allowed
    /// </summary>
    public int? AllowedToHour { get; set; }

    /// <summary>
    /// Timezone for schedule evaluation. Defaults to UTC.
    /// </summary>
    public TimeZoneInfo TimeZone { get; set; } = TimeZoneInfo.Utc;

    /// <summary>
    /// Checks if access is currently allowed based on the schedule
    /// </summary>
    public bool IsAccessAllowed()
    {
        var now = TimeZoneInfo.ConvertTimeFromUtc(DateTime.UtcNow, TimeZone);

        // Check day restriction
        if (AllowedDays.Count > 0 && !AllowedDays.Contains(now.DayOfWeek))
        {
            return false;
        }

        // Check hour restriction
        if (AllowedFromHour.HasValue && AllowedToHour.HasValue)
        {
            var currentHour = now.Hour;
            if (AllowedFromHour <= AllowedToHour)
            {
                // Same day range (e.g., 9-17)
                if (currentHour < AllowedFromHour || currentHour >= AllowedToHour)
                {
                    return false;
                }
            }
            else
            {
                // Overnight range (e.g., 22-6)
                if (currentHour < AllowedFromHour && currentHour >= AllowedToHour)
                {
                    return false;
                }
            }
        }

        return true;
    }
}