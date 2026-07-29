using AspNetCore.BasicAuthentication.Options;
using Shouldly;

namespace AspNetCore.BasicAuthentication.Tests;

public class RememberMeTests
{
    [Fact]
    public void WithRememberMe_ShouldEnableFeatureWithDefaults()
    {
        // Arrange
        var options = new BasicAuthenticationOptions();

        // Act
        options.WithRememberMe(_ => { });

        // Assert
        options.RememberMe.ShouldNotBeNull();
        options.RememberMe!.CookieName.ShouldBe(".BasicAuthGuard.Remember");
        options.RememberMe.Duration.ShouldBe(TimeSpan.FromDays(14));
        options.RememberMe.SlidingExpiration.ShouldBeFalse();
    }

    [Fact]
    public void RememberMe_ShouldBeNullByDefault()
    {
        // Arrange & Act
        var options = new BasicAuthenticationOptions();

        // Assert
        options.RememberMe.ShouldBeNull();
    }

    [Fact]
    public void WithRememberMe_ShouldApplyConfiguration()
    {
        // Arrange
        var options = new BasicAuthenticationOptions();

        // Act
        options.WithRememberMe(remember =>
        {
            remember.CookieName = ".custom";
            remember.Duration = TimeSpan.FromDays(3);
            remember.SlidingExpiration = true;
        });

        // Assert
        options.RememberMe!.CookieName.ShouldBe(".custom");
        options.RememberMe.Duration.ShouldBe(TimeSpan.FromDays(3));
        options.RememberMe.SlidingExpiration.ShouldBeTrue();
    }

    [Fact]
    public void WithRememberMe_CalledTwice_ShouldReuseSameInstance()
    {
        // Arrange
        var options = new BasicAuthenticationOptions();

        // Act
        options.WithRememberMe(remember => remember.CookieName = ".first");
        options.WithRememberMe(remember => remember.SlidingExpiration = true);

        // Assert
        options.RememberMe!.CookieName.ShouldBe(".first");
        options.RememberMe.SlidingExpiration.ShouldBeTrue();
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(366)]
    public void Duration_OutOfRange_ShouldThrow(int days)
    {
        // Arrange
        var options = new RememberMeOptions();

        // Act & Assert
        Should.Throw<ArgumentOutOfRangeException>(() => options.Duration = TimeSpan.FromDays(days));
    }
}
