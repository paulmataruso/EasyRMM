using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace EasyPatch.Infrastructure.Notifications;

/// <summary>
/// Decides which IP addresses a webhook may connect to (SSRF protection). The check runs on the address actually
/// connected to (see <see cref="WebhookHttp"/>), so DNS rebinding cannot bypass it.
/// Always refused: unspecified, loopback, "this network" (0/8), link-local (cloud metadata), multicast, broadcast,
/// reserved (240/4), benchmarking (198.18/15), and the networks of this server's own interfaces (Docker networks with the
/// database). Private ranges (RFC 1918, CGNAT, IPv6 ULA) only when the administrator allows private-network webhooks.
/// </summary>
public static class WebhookAddressPolicy
{
    private static readonly (IPAddress Network, int Prefix)[] AlwaysBlocked =
    [
        (IPAddress.Parse("0.0.0.0"), 8),
        (IPAddress.Parse("127.0.0.0"), 8),
        (IPAddress.Parse("169.254.0.0"), 16),
        (IPAddress.Parse("192.0.0.0"), 24),
        (IPAddress.Parse("192.0.2.0"), 24),
        (IPAddress.Parse("198.18.0.0"), 15),
        (IPAddress.Parse("198.51.100.0"), 24),
        (IPAddress.Parse("203.0.113.0"), 24),
        (IPAddress.Parse("224.0.0.0"), 4),
        (IPAddress.Parse("240.0.0.0"), 4),
        (IPAddress.Parse("::"), 128),
        (IPAddress.Parse("::1"), 128),
        (IPAddress.Parse("fe80::"), 10),
        (IPAddress.Parse("fec0::"), 10),
        (IPAddress.Parse("ff00::"), 8),
        (IPAddress.Parse("100::"), 64),
        (IPAddress.Parse("2001:db8::"), 32),
    ];

    private static readonly (IPAddress Network, int Prefix)[] Private =
    [
        (IPAddress.Parse("10.0.0.0"), 8),
        (IPAddress.Parse("172.16.0.0"), 12),
        (IPAddress.Parse("192.168.0.0"), 16),
        (IPAddress.Parse("100.64.0.0"), 10),
        (IPAddress.Parse("fc00::"), 7),
    ];

    private static readonly IPAddress Nat64 = IPAddress.Parse("64:ff9b::");
    private static readonly IPAddress SixToFour = IPAddress.Parse("2002::");

    /// <summary>Returns null when the address is allowed, otherwise the reason.</summary>
    public static string? Check(IPAddress address, bool allowPrivate, IReadOnlyList<(IPAddress Network, int Prefix)> ownNetworks)
    {
        ArgumentNullException.ThrowIfNull(address);
        ArgumentNullException.ThrowIfNull(ownNetworks);
        foreach (var candidate in Normalize(address))
        {
            if (candidate.Equals(IPAddress.Broadcast) || AlwaysBlocked.Any(n => InNetwork(candidate, n.Network, n.Prefix)))
            {
                return "loopback, link-local, multicast and reserved addresses are not allowed";
            }

            if (ownNetworks.Any(n => InNetwork(candidate, n.Network, n.Prefix)))
            {
                return "addresses on the EasyPatch server's own networks are not allowed";
            }

            if (!allowPrivate && Private.Any(n => InNetwork(candidate, n.Network, n.Prefix)))
            {
                return "private network addresses are not allowed (see Settings → Notifications)";
            }
        }

        return null;
    }

    /// <summary>The address itself plus any IPv4 address embedded in it (IPv4-mapped, NAT64 64:ff9b::/96, 6to4).</summary>
    public static IEnumerable<IPAddress> Normalize(IPAddress address)
    {
        ArgumentNullException.ThrowIfNull(address);
        yield return address;
        if (address.AddressFamily != AddressFamily.InterNetworkV6)
        {
            yield break;
        }

        if (address.IsIPv4MappedToIPv6)
        {
            yield return address.MapToIPv4();
        }

        var bytes = address.GetAddressBytes();
        if (InNetwork(address, Nat64, 96))
        {
            yield return new IPAddress(bytes[12..16]);
        }

        if (InNetwork(address, SixToFour, 16))
        {
            yield return new IPAddress(bytes[2..6]);
        }

        // IPv4-compatible (deprecated ::a.b.c.d)
        if (bytes[..12].All(b => b == 0) && !(bytes[12] == 0 && bytes[13] == 0 && bytes[14] == 0))
        {
            yield return new IPAddress(bytes[12..16]);
        }
    }

    public static bool InNetwork(IPAddress address, IPAddress network, int prefix)
    {
        ArgumentNullException.ThrowIfNull(address);
        ArgumentNullException.ThrowIfNull(network);
        if (address.AddressFamily != network.AddressFamily)
        {
            return false;
        }

        var a = address.GetAddressBytes();
        var n = network.GetAddressBytes();
        var full = prefix / 8;
        for (var i = 0; i < full; i++)
        {
            if (a[i] != n[i])
            {
                return false;
            }
        }

        var rest = prefix % 8;
        if (rest == 0)
        {
            return true;
        }

        var mask = (byte)(0xFF << (8 - rest));
        return (a[full] & mask) == (n[full] & mask);
    }

    /// <summary>Networks of this machine's interfaces (in a container: the Docker networks it is attached to).</summary>
    public static IReadOnlyList<(IPAddress Network, int Prefix)> LocalNetworks()
    {
        var result = new List<(IPAddress, int)>();
        try
        {
            foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                foreach (var unicast in nic.GetIPProperties().UnicastAddresses)
                {
                    var prefix = unicast.PrefixLength;
                    var address = unicast.Address;
                    if (address.IsIPv6LinkLocal || prefix <= 0)
                    {
                        continue;
                    }

                    result.Add((Mask(address, prefix), prefix));
                }
            }
        }
        catch (NetworkInformationException)
        {
            // Without interface information only the static lists apply.
        }

        return result;
    }

    private static IPAddress Mask(IPAddress address, int prefix)
    {
        var bytes = address.GetAddressBytes();
        for (var i = 0; i < bytes.Length; i++)
        {
            var bits = Math.Clamp(prefix - (i * 8), 0, 8);
            bytes[i] &= (byte)(0xFF << (8 - bits));
        }

        return new IPAddress(bytes);
    }
}
