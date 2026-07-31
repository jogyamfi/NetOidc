using NetOidc.Provider.Configuration;

namespace NetOidc.Provider.Tests;

public sealed class ProviderOptionsTests
{
    [Fact]
    public void DefaultEndpoints_AreSet()
    {
        var opts = new ProviderOptions();

        Assert.Equal("/.well-known/openid-configuration", opts.DiscoveryEndpoint);
        Assert.Equal("/.well-known/jwks.json", opts.JwksEndpoint);
        Assert.Equal("/connect/authorize", opts.AuthorizationEndpoint);
        Assert.Equal("/connect/token", opts.TokenEndpoint);
        Assert.Equal("/connect/userinfo", opts.UserInfoEndpoint);
        Assert.Equal("/connect/introspect", opts.IntrospectionEndpoint);
        Assert.Equal("/connect/revoke", opts.RevocationEndpoint);
        Assert.Equal("/connect/end_session", opts.EndSessionEndpoint);
    }

    [Fact]
    public void DefaultTokenLifetimes_AreReasonable()
    {
        var opts = new ProviderOptions();

        Assert.Equal(3600, opts.AccessTokenLifetimeSeconds);
        Assert.Equal(86400, opts.RefreshTokenLifetimeSeconds);
        Assert.Equal(3600, opts.IdTokenLifetimeSeconds);
        Assert.Equal(60, opts.AuthorizationCodeLifetimeSeconds);
    }

    [Fact]
    public void DefaultScopes_ContainOpenId()
    {
        var opts = new ProviderOptions();

        Assert.Contains(opts.Scopes, s => s.Name == "openid");
    }
}
