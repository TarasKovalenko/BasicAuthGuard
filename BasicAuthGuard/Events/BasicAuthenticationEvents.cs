namespace AspNetCore.BasicAuthentication.Events;

/// <summary>
/// Events for BasicAuthGuard authentication handler
/// </summary>
public class BasicAuthenticationEvents
{
    /// <summary>
    /// Invoked when credentials need to be validated
    /// </summary>
    public Func<ValidateCredentialsContext, Task>? OnValidateCredentials { get; set; }

    /// <summary>
    /// Invoked after successful authentication
    /// </summary>
    public Func<AuthenticationSucceededContext, Task>? OnAuthenticationSucceeded { get; set; }

    /// <summary>
    /// Invoked when authentication fails
    /// </summary>
    public Func<AuthenticationFailedContext, Task>? OnAuthenticationFailed { get; set; }

    /// <summary>
    /// Invoked when a challenge is issued
    /// </summary>
    public Func<BasicAuthChallengeContext, Task>? OnChallenge { get; set; }

    /// <summary>
    /// Invoked when forbidden response is returned
    /// </summary>
    public Func<BasicAuthForbiddenContext, Task>? OnForbidden { get; set; }

    /// <summary>
    /// Validates credentials using the configured delegate
    /// </summary>
    public virtual Task ValidateCredentialsAsync(ValidateCredentialsContext context)
        => OnValidateCredentials?.Invoke(context) ?? Task.CompletedTask;

    /// <summary>
    /// Handles successful authentication
    /// </summary>
    public virtual Task AuthenticationSucceededAsync(AuthenticationSucceededContext context)
        => OnAuthenticationSucceeded?.Invoke(context) ?? Task.CompletedTask;

    /// <summary>
    /// Handles authentication failure
    /// </summary>
    public virtual Task AuthenticationFailedAsync(AuthenticationFailedContext context)
        => OnAuthenticationFailed?.Invoke(context) ?? Task.CompletedTask;

    /// <summary>
    /// Handles challenge
    /// </summary>
    public virtual Task ChallengeAsync(BasicAuthChallengeContext context)
        => OnChallenge?.Invoke(context) ?? Task.CompletedTask;

    /// <summary>
    /// Handles forbidden
    /// </summary>
    public virtual Task ForbiddenAsync(BasicAuthForbiddenContext context)
        => OnForbidden?.Invoke(context) ?? Task.CompletedTask;
}