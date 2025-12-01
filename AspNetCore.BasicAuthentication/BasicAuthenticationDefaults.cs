namespace AspNetCore.BasicAuthentication;

/// <summary>
/// Default values for BasicAuthentication
/// </summary>
public class BasicAuthenticationDefaults
{
    /// <summary>
    /// Default authentication scheme name
    /// </summary>
    public const string AuthenticationScheme = "BasicAuthentication";

    /// <summary>
    /// Default realm for WWW-Authenticate header
    /// </summary>
    public const string Realm = "Protected";

    /// <summary>
    /// Default policy name
    /// </summary>
    public const string PolicyName = "BasicAuthenticationPolicy";
}