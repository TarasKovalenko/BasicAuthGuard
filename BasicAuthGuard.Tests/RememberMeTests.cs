using System.Security.Claims;
using AspNetCore.BasicAuthentication.Options;
using AspNetCore.BasicAuthentication.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
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

    [Fact]
    public void Protector_RoundTrip_ShouldPreservePrincipal()
    {
        // Arrange
        var protector = new RememberMeTicketProtector(new EphemeralDataProtectionProvider());
        var ticket = CreateTicket("admin", "Admin");

        // Act
        var value = protector.Protect(ticket, TimeSpan.FromMinutes(5));
        var restored = protector.Unprotect(value);

        // Assert
        restored.ShouldNotBeNull();
        restored!.AuthenticationScheme.ShouldBe("BasicAuthGuard");
        restored.Principal.Identity!.Name.ShouldBe("admin");
        restored.Principal.IsInRole("Admin").ShouldBeTrue();
    }

    [Fact]
    public void Protector_ExpiredTicket_ShouldReturnNull()
    {
        // Arrange
        var protector = new RememberMeTicketProtector(new EphemeralDataProtectionProvider());
        var ticket = CreateTicket("admin", "Admin");

        // Act - a negative lifetime puts the expiry in the past
        var value = protector.Protect(ticket, TimeSpan.FromMinutes(-5));
        var restored = protector.Unprotect(value);

        // Assert
        restored.ShouldBeNull();
    }

    [Fact]
    public void Protector_TamperedValue_ShouldReturnNull()
    {
        // Arrange
        var protector = new RememberMeTicketProtector(new EphemeralDataProtectionProvider());
        var value = protector.Protect(CreateTicket("admin", "Admin"), TimeSpan.FromMinutes(5));
        var tampered = (value[0] == 'A' ? 'B' : 'A') + value.Substring(1);

        // Act
        var restored = protector.Unprotect(tampered);

        // Assert
        restored.ShouldBeNull();
    }

    [Fact]
    public void Protector_ValueFromDifferentKeyring_ShouldReturnNull()
    {
        // Arrange
        var issuer = new RememberMeTicketProtector(new EphemeralDataProtectionProvider());
        var other = new RememberMeTicketProtector(new EphemeralDataProtectionProvider());
        var value = issuer.Protect(CreateTicket("admin", "Admin"), TimeSpan.FromMinutes(5));

        // Act
        var restored = other.Unprotect(value);

        // Assert
        restored.ShouldBeNull();
    }

    [Theory]
    [InlineData("")]
    [InlineData("not-a-valid-cookie-value")]
    public void Protector_MalformedValue_ShouldReturnNull(string value)
    {
        // Arrange
        var protector = new RememberMeTicketProtector(new EphemeralDataProtectionProvider());

        // Act
        var restored = protector.Unprotect(value);

        // Assert
        restored.ShouldBeNull();
    }

    private static AuthenticationTicket CreateTicket(string username, string role)
    {
        var identity = new ClaimsIdentity(
            [new Claim(ClaimTypes.Name, username), new Claim(ClaimTypes.Role, role)],
            "BasicAuthGuard");
        return new AuthenticationTicket(new ClaimsPrincipal(identity), "BasicAuthGuard");
    }
}
