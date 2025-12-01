using System.Net;

namespace AspNetCore.BasicAuthentication.Options;

/// <summary>
/// Configuration options for IP-based access restrictions
/// </summary>
public class IpWhitelistOptions
{
    /// <summary>
    /// List of allowed IP addresses or CIDR ranges (e.g., "192.168.1.0/24", "10.0.0.1")
    /// </summary>
    public IList<string> AllowedRanges { get; set; } = [];

    /// <summary>
    /// List of blocked IP addresses or CIDR ranges
    /// </summary>
    public IList<string> BlockedRanges { get; set; } = [];

    /// <summary>
    /// If true, requests from allowed IPs skip authentication entirely
    /// </summary>
    public bool BypassAuthForAllowedIps { get; set; } = false;

    /// <summary>
    /// If true, requests from IPs not in the whitelist are rejected (when AllowedRanges is not empty)
    /// </summary>
    public bool RejectIfNotWhitelisted { get; set; } = true;

    /// <summary>
    /// Custom response message when IP is blocked
    /// </summary>
    public string? BlockedMessage { get; set; }

    private List<(IPAddress Network, int PrefixLength)>? _parsedAllowedRanges;
    private List<(IPAddress Network, int PrefixLength)>? _parsedBlockedRanges;

    /// <summary>
    /// Checks if the given IP address is allowed
    /// </summary>
    public bool IsIpAllowed(IPAddress? ipAddress)
    {
        if (ipAddress is null)
        {
            return AllowedRanges.Count == 0;
        }

        // Check blocked list first
        _parsedBlockedRanges ??= ParseRanges(BlockedRanges);
        if (_parsedBlockedRanges.Count > 0 && IsInRanges(ipAddress, _parsedBlockedRanges))
        {
            return false;
        }

        // If no whitelist defined, allow all (that aren't blocked)
        if (AllowedRanges.Count == 0)
        {
            return true;
        }

        // Check whitelist
        _parsedAllowedRanges ??= ParseRanges(AllowedRanges);
        return IsInRanges(ipAddress, _parsedAllowedRanges);
    }

    /// <summary>
    /// Checks if authentication should be bypassed for the given IP
    /// </summary>
    public bool ShouldBypassAuth(IPAddress? ipAddress)
    {
        if (!BypassAuthForAllowedIps || ipAddress is null)
        {
            return false;
        }

        _parsedAllowedRanges ??= ParseRanges(AllowedRanges);
        return _parsedAllowedRanges.Count > 0 && IsInRanges(ipAddress, _parsedAllowedRanges);
    }

    private static List<(IPAddress Network, int PrefixLength)> ParseRanges(IList<string> ranges)
    {
        var result = new List<(IPAddress, int)>();

        foreach (var range in ranges)
        {
            var parts = range.Split('/');
            if (IPAddress.TryParse(parts[0], out var address))
            {
                var prefixLength = parts.Length > 1 && int.TryParse(parts[1], out var prefix)
                    ? prefix
                    : (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ? 32 : 128);

                result.Add((address, prefixLength));
            }
        }

        return result;
    }

    private static bool IsInRanges(IPAddress address, List<(IPAddress Network, int PrefixLength)> ranges)
    {
        foreach (var (network, prefixLength) in ranges)
        {
            if (IsInRange(address, network, prefixLength))
            {
                return true;
            }
        }

        return false;
    }

    private static bool IsInRange(IPAddress address, IPAddress network, int prefixLength)
    {
        if (address.AddressFamily != network.AddressFamily)
        {
            return false;
        }

        var addressBytes = address.GetAddressBytes();
        var networkBytes = network.GetAddressBytes();

        var bytesToCompare = prefixLength / 8;
        var remainingBits = prefixLength % 8;

        for (var i = 0; i < bytesToCompare; i++)
        {
            if (addressBytes[i] != networkBytes[i])
            {
                return false;
            }
        }

        if (remainingBits > 0 && bytesToCompare < addressBytes.Length)
        {
            var mask = (byte)(0xFF << (8 - remainingBits));
            if ((addressBytes[bytesToCompare] & mask) != (networkBytes[bytesToCompare] & mask))
            {
                return false;
            }
        }

        return true;
    }
}