using System.Net;
using System.Net.Sockets;

namespace NetOidc.Provider.Http;

/// <summary>
/// Classifies IP addresses so outbound requests to URLs supplied by untrusted parties
/// (dynamically registered clients) cannot reach internal networks (SSRF).
/// </summary>
internal static class NetworkAddressPolicy
{
    /// <summary>Returns <c>true</c> when <paramref name="address"/> is publicly routable.</summary>
    public static bool IsPublic(IPAddress address)
    {
        if (address.IsIPv4MappedToIPv6)
            address = address.MapToIPv4();

        if (IPAddress.IsLoopback(address) ||
            address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any) ||
            address.Equals(IPAddress.None) || address.Equals(IPAddress.IPv6None))
            return false;

        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            var b = address.GetAddressBytes();
            return !(b[0] == 0 ||                                   // 0.0.0.0/8
                     b[0] == 10 ||                                  // 10.0.0.0/8
                     (b[0] == 100 && b[1] >= 64 && b[1] <= 127) ||  // 100.64.0.0/10 (CGNAT)
                     b[0] == 127 ||                                 // loopback
                     (b[0] == 169 && b[1] == 254) ||                // link-local / cloud metadata
                     (b[0] == 172 && b[1] >= 16 && b[1] <= 31) ||   // 172.16.0.0/12
                     (b[0] == 192 && b[1] == 0 && b[2] == 0) ||     // 192.0.0.0/24
                     (b[0] == 192 && b[1] == 168) ||                // 192.168.0.0/16
                     (b[0] == 198 && (b[1] == 18 || b[1] == 19)) || // benchmarking
                     b[0] >= 224);                                  // multicast / reserved
        }

        if (address.AddressFamily == AddressFamily.InterNetworkV6)
        {
            var b = address.GetAddressBytes();
            if (address.IsIPv6LinkLocal || address.IsIPv6SiteLocal || address.IsIPv6Multicast ||
                (b[0] & 0xFE) == 0xFC ||                                         // fc00::/7 unique-local
                b.AsSpan(0, 12).IndexOfAnyExcept((byte)0) < 0 ||                 // ::/96 IPv4-compatible
                (b[0] == 0x01 && b.AsSpan(1, 7).IndexOfAnyExcept((byte)0) < 0) || // 100::/64 discard
                (b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x0D && b[3] == 0xB8) || // 2001:db8::/32 documentation
                (b[0] == 0x20 && b[1] == 0x01 && b[2] == 0 && b[3] == 0))         // 2001::/32 Teredo
                return false;

            // Translation prefixes embed an IPv4 address that the network may route to.
            if (b[0] == 0x00 && b[1] == 0x64 && b[2] == 0xFF && b[3] == 0x9B)    // 64:ff9b::/96 NAT64
                return IsPublic(new IPAddress(b.AsSpan(12, 4)));
            if (b[0] == 0x20 && b[1] == 0x02)                                    // 2002::/16 6to4
                return IsPublic(new IPAddress(b.AsSpan(2, 4)));
            return true;
        }

        return false;
    }

    /// <summary>
    /// Returns <c>true</c> when <paramref name="host"/> is an IP literal or name that
    /// obviously denotes a non-public destination. DNS names are checked at connect time.
    /// </summary>
    public static bool IsObviouslyInternalHost(string host)
    {
        if (host.Equals("localhost", StringComparison.OrdinalIgnoreCase) ||
            host.EndsWith(".localhost", StringComparison.OrdinalIgnoreCase) ||
            host.EndsWith(".local", StringComparison.OrdinalIgnoreCase) ||
            host.EndsWith(".internal", StringComparison.OrdinalIgnoreCase))
            return true;

        return IPAddress.TryParse(host.Trim('[', ']'), out var ip) && !IsPublic(ip);
    }

    /// <summary>
    /// A <see cref="SocketsHttpHandler.ConnectCallback"/> that resolves the host and refuses
    /// to connect to any non-public address (defeats DNS rebinding to internal hosts).
    /// </summary>
    public static async ValueTask<Stream> ConnectPublicOnlyAsync(
        SocketsHttpConnectionContext context, CancellationToken ct)
    {
        var addresses = await Dns.GetHostAddressesAsync(context.DnsEndPoint.Host, ct);
        var target = addresses.FirstOrDefault(IsPublic)
            ?? throw new HttpRequestException(
                $"Refusing to connect to non-public address for host '{context.DnsEndPoint.Host}'.");
        if (addresses.Any(a => !IsPublic(a)))
            throw new HttpRequestException(
                $"Host '{context.DnsEndPoint.Host}' resolves to a non-public address.");

        var socket = new Socket(SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
        try
        {
            await socket.ConnectAsync(new IPEndPoint(target, context.DnsEndPoint.Port), ct);
            return new NetworkStream(socket, ownsSocket: true);
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }
}
