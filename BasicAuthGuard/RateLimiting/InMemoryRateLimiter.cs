using System.Collections.Concurrent;

namespace AspNetCore.BasicAuthentication.RateLimiting;

/// <summary>
/// Service for tracking and enforcing rate limits on authentication attempts
/// </summary>
public interface IRateLimiter
{
    /// <summary>
    /// Checks if the given key is currently locked out
    /// </summary>
    bool IsLockedOut(string key);

    /// <summary>
    /// Records a failed authentication attempt
    /// </summary>
    void RecordFailedAttempt(string key);

    /// <summary>
    /// Resets the failed attempt counter for the given key
    /// </summary>
    void Reset(string key);

    /// <summary>
    /// Gets the remaining lockout time for the given key
    /// </summary>
    TimeSpan? GetRemainingLockoutTime(string key);
}

/// <summary>
/// In-memory implementation of rate limiter
/// </summary>
public class InMemoryRateLimiter : IRateLimiter, IDisposable
{
    private readonly RateLimitOptions _options;
    private readonly ConcurrentDictionary<string, AttemptRecord> _attempts = new();
    private readonly Timer _cleanupTimer;

    /// <summary>
    /// Creates a new instance
    /// </summary>
    public InMemoryRateLimiter(RateLimitOptions options)
    {
        _options = options;
        // Cleanup expired records every minute
        _cleanupTimer = new Timer(CleanupExpiredRecords, null, TimeSpan.FromMinutes(1), TimeSpan.FromMinutes(1));
    }

    /// <inheritdoc />
    public bool IsLockedOut(string key)
    {
        if (!_attempts.TryGetValue(key, out var record))
        {
            return false;
        }

        // Check if lockout has expired
        if (record.LockedUntil.HasValue)
        {
            if (DateTime.UtcNow >= record.LockedUntil.Value)
            {
                Reset(key);
                return false;
            }
            return true;
        }

        return false;
    }

    /// <inheritdoc />
    public void RecordFailedAttempt(string key)
    {
        var now = DateTime.UtcNow;

        _attempts.AddOrUpdate(
            key,
            _ => new AttemptRecord
            {
                Attempts = [now]
            },
            (_, existing) =>
            {
                // Remove attempts outside the window
                var windowStart = now - _options.AttemptWindow;
                existing.Attempts.RemoveAll(a => a < windowStart);

                // Add new attempt
                existing.Attempts.Add(now);

                // Check if we need to lockout
                if (existing.Attempts.Count >= _options.MaxFailedAttempts)
                {
                    existing.LockedUntil = now + _options.LockoutDuration;
                }

                return existing;
            });
    }

    /// <inheritdoc />
    public void Reset(string key)
    {
        _attempts.TryRemove(key, out _);
    }

    /// <inheritdoc />
    public TimeSpan? GetRemainingLockoutTime(string key)
    {
        if (!_attempts.TryGetValue(key, out var record) || !record.LockedUntil.HasValue)
        {
            return null;
        }

        var remaining = record.LockedUntil.Value - DateTime.UtcNow;
        return remaining > TimeSpan.Zero ? remaining : null;
    }

    private void CleanupExpiredRecords(object? state)
    {
        var now = DateTime.UtcNow;
        var keysToRemove = _attempts
            .Where(kvp =>
            {
                var record = kvp.Value;
                // Remove if lockout expired or no recent attempts
                if (record.LockedUntil.HasValue && now >= record.LockedUntil.Value)
                {
                    return true;
                }

                var windowStart = now - _options.AttemptWindow;
                return record.Attempts.All(a => a < windowStart);
            })
            .Select(kvp => kvp.Key)
            .ToList();

        foreach (var key in keysToRemove)
        {
            _attempts.TryRemove(key, out _);
        }
    }

    /// <inheritdoc />
    public void Dispose()
    {
        _cleanupTimer.Dispose();
        GC.SuppressFinalize(this);
    }

    private class AttemptRecord
    {
        public List<DateTime> Attempts { get; init; } = [];
        public DateTime? LockedUntil { get; set; }
    }
}