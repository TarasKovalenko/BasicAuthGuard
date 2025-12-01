using AspNetCore.BasicAuthentication.Middleware;
using AspNetCore.BasicAuthentication.Options;
using Microsoft.AspNetCore.Builder;

namespace AspNetCore.BasicAuthentication.Extensions;

/// <summary>
/// Extension methods for adding URL-based BasicAuthGuard to the application pipeline
/// </summary>
public static class ApplicationBuilderExtensions
{
    /// <summary>
    /// Adds BasicAuthGuard authentication for a specific URL pattern with inline credentials
    /// </summary>
    /// <param name="app">The application builder</param>
    /// <param name="urlPattern">URL pattern to protect (e.g., "/health", "/api/*")</param>
    /// <param name="username">The username</param>
    /// <param name="password">The password</param>
    /// <returns>The application builder</returns>
    public static IApplicationBuilder AddBasicAuthGuard(
        this IApplicationBuilder app,
        string urlPattern,
        string username,
        string password)
    {
        return app.AddBasicAuthGuard(urlPattern, options =>
        {
            options.Username = username;
            options.Password = password;
        });
    }

    /// <summary>
    /// Adds BasicAuthGuard authentication for a specific URL pattern with inline credentials and realm
    /// </summary>
    /// <param name="app">The application builder</param>
    /// <param name="urlPattern">URL pattern to protect (e.g., "/health", "/api/*")</param>
    /// <param name="username">The username</param>
    /// <param name="password">The password</param>
    /// <param name="realm">The realm</param>
    /// <returns>The application builder</returns>
    public static IApplicationBuilder AddBasicAuthGuard(
        this IApplicationBuilder app,
        string urlPattern,
        string username,
        string password,
        string realm)
    {
        return app.AddBasicAuthGuard(urlPattern, options =>
        {
            options.Username = username;
            options.Password = password;
            options.Realm = realm;
        });
    }

    /// <summary>
    /// Adds BasicAuthGuard authentication for a specific URL pattern with configuration delegate
    /// </summary>
    /// <param name="app">The application builder</param>
    /// <param name="urlPattern">URL pattern to protect (e.g., "/health", "/api/*")</param>
    /// <param name="configure">Configuration delegate</param>
    /// <returns>The application builder</returns>
    public static IApplicationBuilder AddBasicAuthGuard(
        this IApplicationBuilder app,
        string urlPattern,
        Action<UrlBasicAuthenticationOptions> configure)
    {
        var options = new UrlBasicAuthenticationOptions
        {
            UrlPattern = urlPattern
        };
        configure(options);

        var entry = new UrlBasicAuthenticationEntry(options);
        var entries = new List<UrlBasicAuthenticationEntry> { entry };

        return app.UseMiddleware<UrlBasicAuthenticationMiddleware>(entries);
    }

    /// <summary>
    /// Uses BasicAuthGuard middleware with pre-configured URL patterns
    /// </summary>
    /// <param name="app">The application builder</param>
    /// <param name="configureEntries">Configuration delegate for multiple URL patterns</param>
    /// <returns>The application builder</returns>
    public static IApplicationBuilder UseBasicAuthGuard(
        this IApplicationBuilder app,
        Action<UrlBasicAuthenticationBuilder> configureEntries)
    {
        var builder = new UrlBasicAuthenticationBuilder();
        configureEntries(builder);

        if (builder.Entries.Count > 0)
        {
            app.UseMiddleware<UrlBasicAuthenticationMiddleware>(builder.Entries);
        }

        return app;
    }
}

/// <summary>
/// Builder for configuring multiple URL-based authentication entries
/// </summary>
public class UrlBasicAuthenticationBuilder
{
    internal List<UrlBasicAuthenticationEntry> Entries { get; } = [];

    /// <summary>
    /// Adds BasicAuthGuard for a URL pattern with inline credentials
    /// </summary>
    /// <param name="urlPattern">URL pattern to protect</param>
    /// <param name="username">The username</param>
    /// <param name="password">The password</param>
    /// <returns>The builder</returns>
    public UrlBasicAuthenticationBuilder AddPattern(string urlPattern, string username, string password)
    {
        return AddPattern(urlPattern, options =>
        {
            options.Username = username;
            options.Password = password;
        });
    }

    /// <summary>
    /// Adds BasicAuthGuard for a URL pattern with configuration delegate
    /// </summary>
    /// <param name="urlPattern">URL pattern to protect</param>
    /// <param name="configure">Configuration delegate</param>
    /// <returns>The builder</returns>
    public UrlBasicAuthenticationBuilder AddPattern(string urlPattern, Action<UrlBasicAuthenticationOptions> configure)
    {
        var options = new UrlBasicAuthenticationOptions
        {
            UrlPattern = urlPattern
        };
        configure(options);

        Entries.Add(new UrlBasicAuthenticationEntry(options));
        return this;
    }
}
