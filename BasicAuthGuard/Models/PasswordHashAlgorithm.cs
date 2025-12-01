namespace AspNetCore.BasicAuthentication.Models;

/// <summary>
/// Supported password hashing algorithms
/// </summary>
public enum PasswordHashAlgorithm
{
    /// <summary>
    /// No hashing - plain text comparison (not recommended for production)
    /// </summary>
    None = 0,

    /// <summary>
    /// SHA256 hashing
    /// </summary>
    SHA256 = 1,

    /// <summary>
    /// SHA512 hashing
    /// </summary>
    SHA512 = 2,

    /// <summary>
    /// BCrypt hashing (recommended)
    /// </summary>
    BCrypt = 3
}