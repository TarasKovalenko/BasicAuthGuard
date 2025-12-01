using AspNetCore.BasicAuthentication.Options;
using AspNetCore.BasicAuthentication.RateLimiting;
using Shouldly;

namespace AspNetCore.BasicAuthentication.Tests;

public class RateLimiterTests
{
    [Fact]
    public void IsLockedOut_WithNoAttempts_ShouldReturnFalse()
    {
        // Arrange
        var options = new RateLimitOptions { MaxFailedAttempts = 3 };
        using var rateLimiter = new InMemoryRateLimiter(options);

        // Act
        var result = rateLimiter.IsLockedOut("testkey");

        // Assert
        result.ShouldBeFalse();
    }

    [Fact]
    public void IsLockedOut_AfterMaxFailedAttempts_ShouldReturnTrue()
    {
        // Arrange
        var options = new RateLimitOptions
        {
            MaxFailedAttempts = 3,
            LockoutDuration = TimeSpan.FromMinutes(15)
        };
        using var rateLimiter = new InMemoryRateLimiter(options);
        var key = "testkey";

        // Act
        rateLimiter.RecordFailedAttempt(key);
        rateLimiter.RecordFailedAttempt(key);
        rateLimiter.RecordFailedAttempt(key);

        // Assert
        rateLimiter.IsLockedOut(key).ShouldBeTrue();
    }

    [Fact]
    public void IsLockedOut_BelowMaxAttempts_ShouldReturnFalse()
    {
        // Arrange
        var options = new RateLimitOptions
        {
            MaxFailedAttempts = 3,
            LockoutDuration = TimeSpan.FromMinutes(15)
        };
        using var rateLimiter = new InMemoryRateLimiter(options);
        var key = "testkey";

        // Act
        rateLimiter.RecordFailedAttempt(key);
        rateLimiter.RecordFailedAttempt(key);

        // Assert
        rateLimiter.IsLockedOut(key).ShouldBeFalse();
    }

    [Fact]
    public void Reset_ShouldClearLockout()
    {
        // Arrange
        var options = new RateLimitOptions
        {
            MaxFailedAttempts = 3,
            LockoutDuration = TimeSpan.FromMinutes(15)
        };
        using var rateLimiter = new InMemoryRateLimiter(options);
        var key = "testkey";

        // Lock out the key
        rateLimiter.RecordFailedAttempt(key);
        rateLimiter.RecordFailedAttempt(key);
        rateLimiter.RecordFailedAttempt(key);
        rateLimiter.IsLockedOut(key).ShouldBeTrue();

        // Act
        rateLimiter.Reset(key);

        // Assert
        rateLimiter.IsLockedOut(key).ShouldBeFalse();
    }

    [Fact]
    public void GetRemainingLockoutTime_WhenLockedOut_ShouldReturnRemainingTime()
    {
        // Arrange
        var options = new RateLimitOptions
        {
            MaxFailedAttempts = 3,
            LockoutDuration = TimeSpan.FromMinutes(15)
        };
        using var rateLimiter = new InMemoryRateLimiter(options);
        var key = "testkey";

        // Lock out the key
        rateLimiter.RecordFailedAttempt(key);
        rateLimiter.RecordFailedAttempt(key);
        rateLimiter.RecordFailedAttempt(key);

        // Act
        var remaining = rateLimiter.GetRemainingLockoutTime(key);

        // Assert
        remaining.ShouldNotBeNull();
        remaining.Value.Minutes.ShouldBeLessThanOrEqualTo(15);
    }

    [Fact]
    public void GetRemainingLockoutTime_WhenNotLockedOut_ShouldReturnNull()
    {
        // Arrange
        var options = new RateLimitOptions { MaxFailedAttempts = 3 };
        using var rateLimiter = new InMemoryRateLimiter(options);

        // Act
        var remaining = rateLimiter.GetRemainingLockoutTime("testkey");

        // Assert
        remaining.ShouldBeNull();
    }
}