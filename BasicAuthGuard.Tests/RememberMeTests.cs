using System.Net;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
using AspNetCore.BasicAuthentication.Extensions;
using AspNetCore.BasicAuthentication.Options;
using AspNetCore.BasicAuthentication.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
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

    [Fact]
    public async Task SuccessfulAuth_WithRememberMeEnabled_ShouldSetCookie()
    {
        // Arrange
        using var host = await CreateHost(remember => remember.SecurePolicy = CookieSecurePolicy.None);
        var client = host.GetTestClient();
        client.DefaultRequestHeaders.Authorization = BasicHeader("admin", "password123");

        // Act
        var response = await client.GetAsync("/secure");

        // Assert
        response.StatusCode.ShouldBe(HttpStatusCode.OK);
        var setCookie = GetSetCookie(response, ".BasicAuthGuard.Remember");
        setCookie.ShouldNotBeNull();
        setCookie!.ShouldContain("httponly", Case.Insensitive);
        setCookie.ShouldContain("expires=", Case.Insensitive);
    }

    [Fact]
    public async Task SuccessfulAuth_WithRememberMeDisabled_ShouldNotSetCookie()
    {
        // Arrange
        using var host = await CreateHost(remember: null);
        var client = host.GetTestClient();
        client.DefaultRequestHeaders.Authorization = BasicHeader("admin", "password123");

        // Act
        var response = await client.GetAsync("/secure");

        // Assert
        response.StatusCode.ShouldBe(HttpStatusCode.OK);
        GetSetCookie(response, ".BasicAuthGuard.Remember").ShouldBeNull();
    }

    [Fact]
    public async Task FailedAuth_ShouldNotSetCookie()
    {
        // Arrange
        using var host = await CreateHost(remember => remember.SecurePolicy = CookieSecurePolicy.None);
        var client = host.GetTestClient();
        client.DefaultRequestHeaders.Authorization = BasicHeader("admin", "wrong-password");

        // Act
        var response = await client.GetAsync("/secure");

        // Assert
        response.StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
        GetSetCookie(response, ".BasicAuthGuard.Remember").ShouldBeNull();
    }

    [Fact]
    public async Task CookieAlone_ShouldAuthenticateWithoutAuthorizationHeader()
    {
        // Arrange
        using var host = await CreateHost(remember => remember.SecurePolicy = CookieSecurePolicy.None);
        var client = host.GetTestClient();
        client.DefaultRequestHeaders.Authorization = BasicHeader("admin", "password123");
        var first = await client.GetAsync("/secure");
        var cookie = CookiePair(GetSetCookie(first, ".BasicAuthGuard.Remember")!);

        // Act - no Authorization header this time
        client.DefaultRequestHeaders.Authorization = null;
        client.DefaultRequestHeaders.Add("Cookie", cookie);
        var second = await client.GetAsync("/secure");

        // Assert
        second.StatusCode.ShouldBe(HttpStatusCode.OK);
        (await second.Content.ReadAsStringAsync()).ShouldBe("admin");
    }

    [Fact]
    public async Task NonSlidingCookie_ShouldNotBeReissuedOnCookieAuth()
    {
        // Arrange
        using var host = await CreateHost(remember => remember.SecurePolicy = CookieSecurePolicy.None);
        var client = host.GetTestClient();
        client.DefaultRequestHeaders.Authorization = BasicHeader("admin", "password123");
        var first = await client.GetAsync("/secure");
        var cookie = CookiePair(GetSetCookie(first, ".BasicAuthGuard.Remember")!);

        // Act
        client.DefaultRequestHeaders.Authorization = null;
        client.DefaultRequestHeaders.Add("Cookie", cookie);
        var second = await client.GetAsync("/secure");

        // Assert
        second.StatusCode.ShouldBe(HttpStatusCode.OK);
        GetSetCookie(second, ".BasicAuthGuard.Remember").ShouldBeNull();
    }

    [Fact]
    public async Task SlidingCookie_ShouldBeReissuedOnCookieAuth()
    {
        // Arrange
        using var host = await CreateHost(remember =>
        {
            remember.SecurePolicy = CookieSecurePolicy.None;
            remember.SlidingExpiration = true;
        });
        var client = host.GetTestClient();
        client.DefaultRequestHeaders.Authorization = BasicHeader("admin", "password123");
        var first = await client.GetAsync("/secure");
        var cookie = CookiePair(GetSetCookie(first, ".BasicAuthGuard.Remember")!);

        // Act
        client.DefaultRequestHeaders.Authorization = null;
        client.DefaultRequestHeaders.Add("Cookie", cookie);
        var second = await client.GetAsync("/secure");

        // Assert
        second.StatusCode.ShouldBe(HttpStatusCode.OK);
        GetSetCookie(second, ".BasicAuthGuard.Remember").ShouldNotBeNull();
    }

    [Fact]
    public async Task GarbageCookie_ShouldReturn401AndClearCookie()
    {
        // Arrange
        using var host = await CreateHost(remember => remember.SecurePolicy = CookieSecurePolicy.None);
        var client = host.GetTestClient();
        client.DefaultRequestHeaders.Add("Cookie", ".BasicAuthGuard.Remember=not-a-real-ticket");

        // Act
        var response = await client.GetAsync("/secure");

        // Assert
        response.StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
        response.Headers.WwwAuthenticate.ShouldNotBeEmpty();
        var setCookie = GetSetCookie(response, ".BasicAuthGuard.Remember");
        setCookie.ShouldNotBeNull();
        setCookie!.ShouldContain("expires=Thu, 01 Jan 1970", Case.Insensitive);
    }

    [Fact]
    public async Task AuthorizationHeader_ShouldWinOverCookie()
    {
        // Arrange - get a cookie for user1, then send it alongside user2's header
        using var host = await CreateMultiUserHost(remember => remember.SecurePolicy = CookieSecurePolicy.None);
        var client = host.GetTestClient();
        client.DefaultRequestHeaders.Authorization = BasicHeader("user1", "pass1");
        var first = await client.GetAsync("/secure");
        var cookie = CookiePair(GetSetCookie(first, ".BasicAuthGuard.Remember")!);

        // Act
        client.DefaultRequestHeaders.Authorization = BasicHeader("user2", "pass2");
        client.DefaultRequestHeaders.Add("Cookie", cookie);
        var second = await client.GetAsync("/secure");

        // Assert
        second.StatusCode.ShouldBe(HttpStatusCode.OK);
        (await second.Content.ReadAsStringAsync()).ShouldBe("user2");
    }

    [Fact]
    public async Task DelegateValidation_ShouldTakePrecedenceOverUsersOnCookieRevalidation()
    {
        // Arrange - a validation delegate is configured alongside a Users entry carrying a
        // role. On the header path, ValidateCredentialsAsync's precedence takes the delegate
        // branch first and never consults Users, so no role claim is attached. The cookie path
        // must mirror that precedence rather than finding the Users entry and granting the role
        // the header-authenticated request never got.
        using var host = await CreateDelegateWithUsersHost();
        var client = host.GetTestClient();
        client.DefaultRequestHeaders.Authorization = BasicHeader("user1", "pass1");
        var first = await client.GetAsync("/roles");
        first.StatusCode.ShouldBe(HttpStatusCode.OK);
        (await first.Content.ReadAsStringAsync()).ShouldBe(string.Empty);
        var cookie = CookiePair(GetSetCookie(first, ".BasicAuthGuard.Remember")!);

        // Act
        client.DefaultRequestHeaders.Authorization = null;
        client.DefaultRequestHeaders.Add("Cookie", cookie);
        var second = await client.GetAsync("/roles");

        // Assert
        second.StatusCode.ShouldBe(HttpStatusCode.OK);
        (await second.Content.ReadAsStringAsync()).ShouldBe(string.Empty);
    }

    [Fact]
    public async Task DisabledUser_ShouldRejectCookieAndClearIt()
    {
        // Arrange
        using var host = await CreateMultiUserHost(remember => remember.SecurePolicy = CookieSecurePolicy.None);
        var client = host.GetTestClient();
        client.DefaultRequestHeaders.Authorization = BasicHeader("user1", "pass1");
        var first = await client.GetAsync("/secure");
        var cookie = CookiePair(GetSetCookie(first, ".BasicAuthGuard.Remember")!);

        // Disable the user after the cookie was issued
        var options = host.Services
            .GetRequiredService<IOptionsMonitor<BasicAuthenticationOptions>>()
            .Get(BasicAuthenticationDefaults.AuthenticationScheme);
        options.Users.First(u => u.Username == "user1").IsEnabled = false;

        // Act
        client.DefaultRequestHeaders.Authorization = null;
        client.DefaultRequestHeaders.Add("Cookie", cookie);
        var second = await client.GetAsync("/secure");

        // Assert
        second.StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
        var setCookie = GetSetCookie(second, ".BasicAuthGuard.Remember");
        setCookie.ShouldNotBeNull();
        setCookie!.ShouldContain("expires=Thu, 01 Jan 1970", Case.Insensitive);
    }

    [Fact]
    public async Task CookieAuth_ShouldRestoreRolesFromCurrentConfiguration()
    {
        // Arrange
        using var host = await CreateMultiUserHost(remember => remember.SecurePolicy = CookieSecurePolicy.None);
        var client = host.GetTestClient();
        client.DefaultRequestHeaders.Authorization = BasicHeader("user1", "pass1");
        var first = await client.GetAsync("/secure");
        var cookie = CookiePair(GetSetCookie(first, ".BasicAuthGuard.Remember")!);

        // Change the user's roles after the cookie was issued - the cookie's stored ticket
        // still carries "Admin", so a response of "Manager" proves the claims were rebuilt
        // from current configuration rather than replayed verbatim from the cookie.
        var options = host.Services
            .GetRequiredService<IOptionsMonitor<BasicAuthenticationOptions>>()
            .Get(BasicAuthenticationDefaults.AuthenticationScheme);
        var user1 = options.Users.First(u => u.Username == "user1");
        user1.Roles = ["Manager"];

        // Act
        client.DefaultRequestHeaders.Authorization = null;
        client.DefaultRequestHeaders.Add("Cookie", cookie);
        var second = await client.GetAsync("/roles");

        // Assert
        second.StatusCode.ShouldBe(HttpStatusCode.OK);
        (await second.Content.ReadAsStringAsync()).ShouldBe("Manager");
    }

    [Fact]
    public async Task IpBypassedRequest_ShouldNotSetCookie()
    {
        // Arrange - CreateIpBypassHost's middleware stamps RemoteIpAddress as loopback, which bypasses auth entirely
        using var host = await CreateIpBypassHost();
        var client = host.GetTestClient();

        // Act
        var response = await client.GetAsync("/secure");

        // Assert
        response.StatusCode.ShouldBe(HttpStatusCode.OK);
        GetSetCookie(response, ".BasicAuthGuard.Remember").ShouldBeNull();
    }

    private static async Task<IHost> CreateIpBypassHost()
    {
        var host = new HostBuilder()
            .ConfigureWebHost(webBuilder =>
            {
                webBuilder.UseTestServer();
                webBuilder.ConfigureServices(services =>
                {
                    services.AddBasicAuthGuard(options =>
                    {
                        options.Username = "admin";
                        options.Password = "password123";
                        options.WithIpWhitelist(whitelist =>
                        {
                            whitelist.AllowedRanges.Add("::1");
                            whitelist.AllowedRanges.Add("127.0.0.1");
                            whitelist.BypassAuthForAllowedIps = true;
                        });
                        options.WithRememberMe(remember => remember.SecurePolicy = CookieSecurePolicy.None);
                    });
                    services.AddBasicAuthGuardPolicy();
                    services.AddAuthorization();
                    services.AddRouting();
                });
                webBuilder.Configure(app =>
                {
                    // TestServer does not populate Connection.RemoteIpAddress by default, so
                    // simulate a loopback client explicitly to exercise the bypass path.
                    app.Use(async (context, next) =>
                    {
                        context.Connection.RemoteIpAddress = IPAddress.Loopback;
                        await next();
                    });
                    app.UseRouting();
                    app.UseAuthentication();
                    app.UseAuthorization();
                    app.UseEndpoints(endpoints =>
                    {
                        endpoints.MapGet("/secure", (HttpContext ctx) => ctx.User.Identity!.Name)
                            .RequireBasicAuth();
                    });
                });
            })
            .Build();

        await host.StartAsync();
        return host;
    }

    private static async Task<IHost> CreateMultiUserHost(Action<RememberMeOptions> remember)
    {
        var host = new HostBuilder()
            .ConfigureWebHost(webBuilder =>
            {
                webBuilder.UseTestServer();
                webBuilder.ConfigureServices(services =>
                {
                    services.AddBasicAuthGuard(options =>
                    {
                        options.AddUser("user1", "pass1", ["Admin"]);
                        options.AddUser("user2", "pass2");
                        options.WithRememberMe(remember);
                    });
                    services.AddBasicAuthGuardPolicy();
                    services.AddAuthorization();
                    services.AddRouting();
                });
                webBuilder.Configure(app =>
                {
                    app.UseRouting();
                    app.UseAuthentication();
                    app.UseAuthorization();
                    app.UseEndpoints(endpoints =>
                    {
                        endpoints.MapGet("/secure", (HttpContext ctx) => ctx.User.Identity!.Name)
                            .RequireBasicAuth();

                        endpoints.MapGet("/roles", (HttpContext ctx) =>
                                string.Join(",", ctx.User.FindAll(System.Security.Claims.ClaimTypes.Role)
                                    .Select(c => c.Value)))
                            .RequireBasicAuth();
                    });
                });
            })
            .Build();

        await host.StartAsync();
        return host;
    }

    private static async Task<IHost> CreateDelegateWithUsersHost()
    {
        var host = new HostBuilder()
            .ConfigureWebHost(webBuilder =>
            {
                webBuilder.UseTestServer();
                webBuilder.ConfigureServices(services =>
                {
                    services.AddBasicAuthGuard(options =>
                    {
                        options.ValidateCredentialsAsync = (username, password, _) =>
                            Task.FromResult(username == "user1" && password == "pass1");
                        options.AddUser("user1", "pass1", ["Admin"]);
                        options.WithRememberMe(remember => remember.SecurePolicy = CookieSecurePolicy.None);
                    });
                    services.AddBasicAuthGuardPolicy();
                    services.AddAuthorization();
                    services.AddRouting();
                });
                webBuilder.Configure(app =>
                {
                    app.UseRouting();
                    app.UseAuthentication();
                    app.UseAuthorization();
                    app.UseEndpoints(endpoints =>
                    {
                        endpoints.MapGet("/roles", (HttpContext ctx) =>
                                string.Join(",", ctx.User.FindAll(ClaimTypes.Role)
                                    .Select(c => c.Value)))
                            .RequireBasicAuth();
                    });
                });
            })
            .Build();

        await host.StartAsync();
        return host;
    }

    private static AuthenticationHeaderValue BasicHeader(string username, string password) =>
        new("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes($"{username}:{password}")));

    private static string? GetSetCookie(HttpResponseMessage response, string cookieName)
    {
        if (!response.Headers.TryGetValues("Set-Cookie", out var values))
        {
            return null;
        }

        return values.FirstOrDefault(v => v.StartsWith(cookieName + "=", StringComparison.Ordinal));
    }

    /// <summary>
    /// Returns the "name=value" pair from a Set-Cookie header, ready to send back as a Cookie header.
    /// </summary>
    private static string CookiePair(string setCookieHeader) => setCookieHeader.Split(';')[0];

    private static async Task<IHost> CreateHost(Action<RememberMeOptions>? remember)
    {
        var host = new HostBuilder()
            .ConfigureWebHost(webBuilder =>
            {
                webBuilder.UseTestServer();
                webBuilder.ConfigureServices(services =>
                {
                    services.AddBasicAuthGuard(options =>
                    {
                        options.Username = "admin";
                        options.Password = "password123";

                        if (remember != null)
                        {
                            options.WithRememberMe(remember);
                        }
                    });
                    services.AddBasicAuthGuardPolicy();
                    services.AddAuthorization();
                    services.AddRouting();
                });
                webBuilder.Configure(app =>
                {
                    app.UseRouting();
                    app.UseAuthentication();
                    app.UseAuthorization();
                    app.UseEndpoints(endpoints =>
                    {
                        endpoints.MapGet("/secure", (HttpContext ctx) => ctx.User.Identity!.Name)
                            .RequireBasicAuth();
                    });
                });
            })
            .Build();

        await host.StartAsync();
        return host;
    }
}
