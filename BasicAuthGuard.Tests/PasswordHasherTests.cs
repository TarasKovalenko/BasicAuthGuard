using AspNetCore.BasicAuthentication.Models;
using AspNetCore.BasicAuthentication.Services;
using Shouldly;

namespace AspNetCore.BasicAuthentication.Tests;

public class PasswordHasherTests
{
    private readonly PasswordHasher _hasher = new();

    [Fact]
    public void Hash_WithNone_ShouldReturnPlainText()
    {
        // Arrange
        const string password = "password123";

        // Act
        var hash = _hasher.Hash(password, PasswordHashAlgorithm.None);

        // Assert
        hash.ShouldBe(password);
    }

    [Fact]
    public void Verify_WithNone_ShouldCompareDirectly()
    {
        // Arrange
        const string password = "password123";

        // Act
        var result = _hasher.Verify(password, password, PasswordHashAlgorithm.None);

        // Assert
        result.ShouldBeTrue();
    }

    [Fact]
    public void Hash_WithSha256_ShouldReturnHash()
    {
        // Arrange
        const string password = "password123";

        // Act
        var hash = _hasher.Hash(password, PasswordHashAlgorithm.SHA256);

        // Assert
        hash.ShouldNotBe(password);
        hash.ShouldNotBeNullOrEmpty();
    }

    [Fact]
    public void Verify_WithSha256_ValidPassword_ShouldReturnTrue()
    {
        // Arrange
        const string password = "password123";
        var hash = _hasher.Hash(password, PasswordHashAlgorithm.SHA256);

        // Act
        var result = _hasher.Verify(password, hash, PasswordHashAlgorithm.SHA256);

        // Assert
        result.ShouldBeTrue();
    }

    [Fact]
    public void Verify_WithSha256_InvalidPassword_ShouldReturnFalse()
    {
        // Arrange
        const string password = "password123";
        var hash = _hasher.Hash(password, PasswordHashAlgorithm.SHA256);

        // Act
        var result = _hasher.Verify("wrongpassword", hash, PasswordHashAlgorithm.SHA256);

        // Assert
        result.ShouldBeFalse();
    }

    [Fact]
    public void Hash_WithSha512_ShouldReturnHash()
    {
        // Arrange
        const string password = "password123";

        // Act
        var hash = _hasher.Hash(password, PasswordHashAlgorithm.SHA512);

        // Assert
        hash.ShouldNotBe(password);
        hash.ShouldNotBeNullOrEmpty();
    }

    [Fact]
    public void Verify_WithSha512_ValidPassword_ShouldReturnTrue()
    {
        // Arrange
        const string password = "password123";
        var hash = _hasher.Hash(password, PasswordHashAlgorithm.SHA512);

        // Act
        var result = _hasher.Verify(password, hash, PasswordHashAlgorithm.SHA512);

        // Assert
        result.ShouldBeTrue();
    }

    [Fact]
    public void Hash_WithBCrypt_ShouldReturnHash()
    {
        // Arrange
        const string password = "password123";

        // Act
        var hash = _hasher.Hash(password, PasswordHashAlgorithm.BCrypt);

        // Assert
        hash.ShouldNotBe(password);
        hash.ShouldNotBeNullOrEmpty();
    }

    [Fact]
    public void Verify_WithBCrypt_ValidPassword_ShouldReturnTrue()
    {
        // Arrange
        const string password = "password123";
        var hash = _hasher.Hash(password, PasswordHashAlgorithm.BCrypt);

        // Act
        var result = _hasher.Verify(password, hash, PasswordHashAlgorithm.BCrypt);

        // Assert
        result.ShouldBeTrue();
    }

    [Fact]
    public void Verify_WithBCrypt_InvalidPassword_ShouldReturnFalse()
    {
        // Arrange
        const string password = "password123";
        var hash = _hasher.Hash(password, PasswordHashAlgorithm.BCrypt);

        // Act
        var result = _hasher.Verify("wrongpassword", hash, PasswordHashAlgorithm.BCrypt);

        // Assert
        result.ShouldBeFalse();
    }

    [Fact]
    public void Hash_WithBCrypt_ShouldProduceDifferentHashesForSamePassword()
    {
        // Arrange
        const string password = "password123";

        // Act
        var hash1 = _hasher.Hash(password, PasswordHashAlgorithm.BCrypt);
        var hash2 = _hasher.Hash(password, PasswordHashAlgorithm.BCrypt);

        // Assert
        // Due to random salt
        hash1.ShouldNotBe(hash2); 
    }

    [Fact]
    public void Verify_WithBCrypt_InvalidHashFormat_ShouldReturnFalse()
    {
        // Arrange
        const string password = "password123";
        const string invalidHash = "not-a-valid-hash";

        // Act
        var result = _hasher.Verify(password, invalidHash, PasswordHashAlgorithm.BCrypt);

        // Assert
        result.ShouldBeFalse();
    }
}