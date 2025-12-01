using AspNetCore.BasicAuthentication.RateLimiting;
using AspNetCore.BasicAuthentication.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace AspNetCore.BasicAuthentication.Extensions;

/// <summary>
/// Extension methods for adding BasicAuthGuard to the service collection
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Adds BasicAuthGuard authentication with inline credentials
    /// </summary>
    /// <param name="services">The service collection</param>
    /// <param name="username">The username</param>
    /// <param name="password">The password</param>
    /// <returns>The authentication builder</returns>
    public static AuthenticationBuilder AddBasicAuthGuard(
        this IServiceCollection services,
        string username,
        string password)
    {
        return services.AddBasicAuthGuard(options =>
        {
            options.Username = username;
            options.Password = password;
        });
    }

    /// <summary>
    /// Adds BasicAuthGuard authentication with inline credentials and realm
    /// </summary>
    /// <param name="services">The service collection</param>
    /// <param name="username">The username</param>
    /// <param name="password">The password</param>
    /// <param name="realm">The realm</param>
    /// <returns>The authentication builder</returns>
    public static AuthenticationBuilder AddBasicAuthGuard(
        this IServiceCollection services,
        string username,
        string password,
        string realm)
    {
        return services.AddBasicAuthGuard(options =>
        {
            options.Username = username;
            options.Password = password;
            options.Realm = realm;
        });
    }

    /// <summary>
    /// Adds BasicAuthGuard authentication with configuration delegate
    /// </summary>
    /// <param name="services">The service collection</param>
    /// <param name="configure">Configuration delegate</param>
    /// <returns>The authentication builder</returns>
    public static AuthenticationBuilder AddBasicAuthGuard(
        this IServiceCollection services,
        Action<BasicAuthenticationOptions> configure)
    {
        return services.AddBasicAuthGuard(BasicAuthenticationDefaults.AuthenticationScheme, configure);
    }

    /// <summary>
    /// Adds BasicAuthGuard authentication with custom scheme name
    /// </summary>
    /// <param name="services">The service collection</param>
    /// <param name="schemeName">The authentication scheme name</param>
    /// <param name="configure">Configuration delegate</param>
    /// <returns>The authentication builder</returns>
    public static AuthenticationBuilder AddBasicAuthGuard(
        this IServiceCollection services,
        string schemeName,
        Action<BasicAuthenticationOptions> configure)
    {
        // Register required services
        services.TryAddSingleton<IPasswordHasher, PasswordHasher>();

        // Configure options to check if rate limiting is needed
        var options = new BasicAuthenticationOptions();
        configure(options);

        if (options.RateLimiting != null)
        {
            services.TryAddSingleton<IRateLimiter>(sp =>
                new InMemoryRateLimiter(options.RateLimiting));
        }

        if (options.AuditLog != null)
        {
            services.TryAddSingleton<IAuditLogger>(sp =>
                new AuditLogger(
                    sp.GetRequiredService<Microsoft.Extensions.Logging.ILogger<AuditLogger>>(),
                    options.AuditLog));
        }

        return services
            .AddAuthentication(schemeName)
            .AddScheme<BasicAuthenticationOptions, BasicAuthenticationHandler>(schemeName, configure);
    }

    /// <summary>
    /// Adds BasicAuthGuard authentication from configuration section
    /// </summary>
    /// <param name="services">The service collection</param>
    /// <param name="configuration">The configuration section</param>
    /// <returns>The authentication builder</returns>
    public static AuthenticationBuilder AddBasicAuthGuard(
        this IServiceCollection services,
        IConfigurationSection configuration)
    {
        return services.AddBasicAuthGuard(options => { configuration.Bind(options); });
    }

    /// <summary>
    /// Adds BasicAuthGuard to an existing authentication builder
    /// </summary>
    /// <param name="builder">The authentication builder</param>
    /// <param name="configure">Configuration delegate</param>
    /// <returns>The authentication builder</returns>
    public static AuthenticationBuilder AddBasicAuthGuard(
        this AuthenticationBuilder builder,
        Action<BasicAuthenticationOptions> configure)
    {
        return builder.AddBasicAuthGuard(BasicAuthenticationDefaults.AuthenticationScheme, configure);
    }

    /// <summary>
    /// Adds BasicAuthGuard to an existing authentication builder with custom scheme name
    /// </summary>
    /// <param name="builder">The authentication builder</param>
    /// <param name="schemeName">The authentication scheme name</param>
    /// <param name="configure">Configuration delegate</param>
    /// <returns>The authentication builder</returns>
    public static AuthenticationBuilder AddBasicAuthGuard(
        this AuthenticationBuilder builder,
        string schemeName,
        Action<BasicAuthenticationOptions> configure)
    {
        // Register required services
        builder.Services.TryAddSingleton<IPasswordHasher, PasswordHasher>();

        // Configure options to check if rate limiting is needed
        var options = new BasicAuthenticationOptions();
        configure(options);

        if (options.RateLimiting != null)
        {
            builder.Services.TryAddSingleton<IRateLimiter>(sp =>
                new InMemoryRateLimiter(options.RateLimiting));
        }

        if (options.AuditLog != null)
        {
            builder.Services.TryAddSingleton<IAuditLogger>(sp =>
                new AuditLogger(
                    sp.GetRequiredService<Microsoft.Extensions.Logging.ILogger<AuditLogger>>(),
                    options.AuditLog));
        }

        return builder.AddScheme<BasicAuthenticationOptions, BasicAuthenticationHandler>(schemeName, configure);
    }

    /// <summary>
    /// Adds BasicAuthGuard authorization policy
    /// </summary>
    /// <param name="services">The service collection</param>
    /// <param name="policyName">The policy name (default: BasicAuthGuardPolicy)</param>
    /// <param name="schemeName">The authentication scheme name (default: BasicAuthGuard)</param>
    /// <returns>The service collection</returns>
    public static IServiceCollection AddBasicAuthGuardPolicy(
        this IServiceCollection services,
        string policyName = BasicAuthenticationDefaults.PolicyName,
        string schemeName = BasicAuthenticationDefaults.AuthenticationScheme)
    {
        services.AddAuthorizationBuilder()
            .AddPolicy(policyName, policy =>
            {
                policy.AddAuthenticationSchemes(schemeName);
                policy.RequireAuthenticatedUser();
            });

        return services;
    }
}