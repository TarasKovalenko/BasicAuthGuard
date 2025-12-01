using System.Security.Cryptography;
using System.Text;

namespace AspNetCore.BasicAuthentication.Services;

/// <summary>
/// Service for password hashing and verification
/// </summary>
public interface IPasswordHasher
{
    /// <summary>
    /// Hashes a password using the specified algorithm
    /// </summary>
    string Hash(string password, PasswordHashAlgorithm algorithm);

    /// <summary>
    /// Verifies a password against a hash
    /// </summary>
    bool Verify(string password, string hash, PasswordHashAlgorithm algorithm);
}

/// <summary>
/// Default implementation of password hasher
/// </summary>
public class PasswordHasher : IPasswordHasher
{
    /// <inheritdoc />
    public string Hash(string password, PasswordHashAlgorithm algorithm)
    {
        return algorithm switch
        {
            PasswordHashAlgorithm.None => password,
            PasswordHashAlgorithm.SHA256 => HashSha256(password),
            PasswordHashAlgorithm.SHA512 => HashSha512(password),
            PasswordHashAlgorithm.BCrypt => HashBCrypt(password),
            _ => throw new ArgumentOutOfRangeException(nameof(algorithm))
        };
    }

    /// <inheritdoc />
    public bool Verify(string password, string hash, PasswordHashAlgorithm algorithm)
    {
        return algorithm switch
        {
            PasswordHashAlgorithm.None => password == hash,
            PasswordHashAlgorithm.SHA256 => VerifySha256(password, hash),
            PasswordHashAlgorithm.SHA512 => VerifySha512(password, hash),
            PasswordHashAlgorithm.BCrypt => VerifyBCrypt(password, hash),
            _ => throw new ArgumentOutOfRangeException(nameof(algorithm))
        };
    }

    private static string HashSha256(string password)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(password));
        return Convert.ToBase64String(bytes);
    }

    private static bool VerifySha256(string password, string hash)
    {
        var computedHash = HashSha256(password);
        return CryptographicOperations.FixedTimeEquals(
            Encoding.UTF8.GetBytes(computedHash),
            Encoding.UTF8.GetBytes(hash));
    }

    private static string HashSha512(string password)
    {
        var bytes = SHA512.HashData(Encoding.UTF8.GetBytes(password));
        return Convert.ToBase64String(bytes);
    }

    private static bool VerifySha512(string password, string hash)
    {
        var computedHash = HashSha512(password);
        return CryptographicOperations.FixedTimeEquals(
            Encoding.UTF8.GetBytes(computedHash),
            Encoding.UTF8.GetBytes(hash));
    }

    private static string HashBCrypt(string password)
    {
        // Using PBKDF2-based implementation
        var salt = RandomNumberGenerator.GetBytes(16);
        var hash = Rfc2898DeriveBytes.Pbkdf2(
            password,
            salt,
            iterations: 100000,
            HashAlgorithmName.SHA256,
            outputLength: 32);

        var result = new byte[48];
        Buffer.BlockCopy(salt, 0, result, 0, 16);
        Buffer.BlockCopy(hash, 0, result, 16, 32);

        return Convert.ToBase64String(result);
    }

    private static bool VerifyBCrypt(string password, string hash)
    {
        try
        {
            var hashBytes = Convert.FromBase64String(hash);
            if (hashBytes.Length != 48)
            {
                return false;
            }

            var salt = hashBytes[..16];
            var storedHash = hashBytes[16..];

            var computedHash = Rfc2898DeriveBytes.Pbkdf2(
                password,
                salt,
                iterations: 100000,
                HashAlgorithmName.SHA256,
                outputLength: 32);

            return CryptographicOperations.FixedTimeEquals(computedHash, storedHash);
        }
        catch
        {
            return false;
        }
    }
}