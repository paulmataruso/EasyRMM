using EasyPatch.Infrastructure.Services;
using Xunit;

namespace EasyPatch.Tests.Unit;

/// <summary>The WebAuthn relying party (ID and origin) comes from the console's public URL; browsers need HTTPS and a DNS name.</summary>
public sealed class WebAuthnAvailabilityTests
{
    [Theory]
    [InlineData("https://patch.example.com", "patch.example.com", "https://patch.example.com")]
    [InlineData("https://Patch.Example.COM:443/", "patch.example.com", "https://patch.example.com")]
    [InlineData("https://patch.example.com:8443", "patch.example.com", "https://patch.example.com:8443")]
    [InlineData("https://localhost:8443", "localhost", "https://localhost:8443")]
    [InlineData("https://bücher.example", "xn--bcher-kva.example", "https://xn--bcher-kva.example")]
    public void A_domain_name_over_https_is_the_relying_party(string publicUrl, string rpId, string origin)
    {
        var availability = WebAuthnAvailability.FromPublicUrl(publicUrl);
        Assert.True(availability.Available);
        Assert.Equal((rpId, origin), (availability.RpId, availability.Origin));
    }

    [Theory]
    [InlineData("https://172.16.0.45:8443", "ip_address")]
    [InlineData("https://[2001:db8::1]", "ip_address")]
    [InlineData("http://patch.example.com", "not_https")]
    [InlineData("", "invalid_public_url")]
    [InlineData(null, "invalid_public_url")]
    public void Ip_addresses_plain_http_and_bad_urls_are_unavailable(string? publicUrl, string reason)
    {
        var availability = WebAuthnAvailability.FromPublicUrl(publicUrl);
        Assert.False(availability.Available);
        Assert.Equal(reason, availability.Reason);
        Assert.False(string.IsNullOrEmpty(availability.Message));
        Assert.Null(availability.RpId);
    }
}
