using System.Net;
using System.Net.Http.Headers;
using System.Text;
using AspNetCore.BasicAuthentication.Extensions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Shouldly;

namespace AspNetCore.BasicAuthentication.Tests;

public class BasicAuthenticationTests
{
    [Fact]
    public async Task ValidCredentials_ShouldReturn200()
    {
        // Arrange
        using var host = await CreateHost("admin", "password123");
        var client = host.GetTestClient();

        // Act
        client.DefaultRequestHeaders.Authorization = CreateBasicAuthHeader("admin", "password123");
        var response = await client.GetAsync("/secure");

        // Assert
        response.StatusCode.ShouldBe(HttpStatusCode.OK);
    }

    [Fact]
    public async Task InvalidCredentials_ShouldReturn401()
    {
        // Arrange
        using var host = await CreateHost("admin", "password123");
        var client = host.GetTestClient();

        // Act
        client.DefaultRequestHeaders.Authorization = CreateBasicAuthHeader("admin", "wrongpassword");
        var response = await client.GetAsync("/secure");

        // Assert
        response.StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task MissingCredentials_ShouldReturn401WithWwwAuthenticateHeader()
    {
        // Arrange
        using var host = await CreateHost("admin", "password123");
        var client = host.GetTestClient();

        // Act
        var response = await client.GetAsync("/secure");

        // Assert
        response.StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
        response.Headers.WwwAuthenticate.ShouldNotBeEmpty();
        response.Headers.WwwAuthenticate.First().Scheme.ShouldBe("Basic");
    }

    [Fact]
    public async Task PublicEndpoint_ShouldReturn200WithoutAuth()
    {
        // Arrange
        using var host = await CreateHost("admin", "password123");
        var client = host.GetTestClient();

        // Act
        var response = await client.GetAsync("/public");

        // Assert
        response.StatusCode.ShouldBe(HttpStatusCode.OK);
    }

    [Fact]
    public async Task PerEndpointAuth_ShouldUseEndpointCredentials()
    {
        // Arrange
        using var host = await CreateHostWithPerEndpointAuth();
        var client = host.GetTestClient();

        // Act - Try endpoint1 with endpoint1 credentials
        client.DefaultRequestHeaders.Authorization = CreateBasicAuthHeader("user1", "pass1");
        var response1 = await client.GetAsync("/endpoint1");

        // Act - Try endpoint2 with endpoint2 credentials
        client.DefaultRequestHeaders.Authorization = CreateBasicAuthHeader("user2", "pass2");
        var response2 = await client.GetAsync("/endpoint2");

        // Assert
        response1.StatusCode.ShouldBe(HttpStatusCode.OK);
        response2.StatusCode.ShouldBe(HttpStatusCode.OK);
    }

    [Fact]
    public async Task PerEndpointAuth_WrongCredentials_ShouldReturn401()
    {
        // Arrange
        using var host = await CreateHostWithPerEndpointAuth();
        var client = host.GetTestClient();

        // Act - Try endpoint1 with endpoint2 credentials
        client.DefaultRequestHeaders.Authorization = CreateBasicAuthHeader("user2", "pass2");
        var response = await client.GetAsync("/endpoint1");

        // Assert
        response.StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
    }

    private static AuthenticationHeaderValue CreateBasicAuthHeader(string username, string password)
    {
        var credentials = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{username}:{password}"));
        return new AuthenticationHeaderValue("Basic", credentials);
    }

    private static async Task<IHost> CreateHost(string username, string password)
    {
        var host = new HostBuilder()
            .ConfigureWebHost(webBuilder =>
            {
                webBuilder.UseTestServer();
                webBuilder.ConfigureServices(services =>
                {
                    services.AddBasicAuthGuard(username, password);
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
                        endpoints.MapGet("/secure", () => "Secret!")
                            .RequireBasicAuth();

                        endpoints.MapGet("/public", () => "Public!");
                    });
                });
            })
            .Build();

        await host.StartAsync();
        return host;
    }

    private static async Task<IHost> CreateHostWithPerEndpointAuth()
    {
        var host = new HostBuilder()
            .ConfigureWebHost(webBuilder =>
            {
                webBuilder.UseTestServer();
                webBuilder.ConfigureServices(services =>
                {
                    services.AddRouting();
                    services.AddAuthorization();
                });
                webBuilder.Configure(app =>
                {
                    app.UseRouting();
                    app.UseEndpoints(endpoints =>
                    {
                        endpoints.MapGet("/endpoint1", () => "Endpoint 1")
                            .RequireBasicAuth("user1", "pass1");

                        endpoints.MapGet("/endpoint2", () => "Endpoint 2")
                            .RequireBasicAuth("user2", "pass2");
                    });
                });
            })
            .Build();

        await host.StartAsync();
        return host;
    }
}