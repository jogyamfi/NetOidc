namespace NetOidc.Provider.Configuration;

/// <summary>Input to <see cref="ProviderOptions.AuthorizeTokenExchange"/> (RFC 8693).</summary>
/// <param name="ClientId">The authenticated client requesting the exchange.</param>
/// <param name="SubjectTokenClientId">The client the subject token was issued to.</param>
/// <param name="Subject">The subject of the subject token, or <c>null</c> for client tokens.</param>
/// <param name="SubjectTokenType">The RFC 8693 token type URI of the subject token.</param>
/// <param name="SubjectTokenScopes">Scopes carried by the subject token.</param>
/// <param name="RequestedScopes">Scopes that would be granted to the new token.</param>
/// <param name="Audiences">Values of the <c>audience</c> request parameter.</param>
/// <param name="Resources">Values of the <c>resource</c> request parameter.</param>
public sealed record TokenExchangeContext(
    string ClientId,
    string SubjectTokenClientId,
    string? Subject,
    string SubjectTokenType,
    IReadOnlyList<string> SubjectTokenScopes,
    IReadOnlyList<string> RequestedScopes,
    IReadOnlyList<string> Audiences,
    IReadOnlyList<string> Resources);

/// <summary>Input to <see cref="ProviderOptions.AuthorizeIntrospection"/> (RFC 7662 §4).</summary>
/// <param name="CallerClientId">The authenticated client calling the introspection endpoint.</param>
/// <param name="TokenClientId">The client the token was issued to.</param>
/// <param name="Subject">The token's subject, or <c>null</c> for client tokens.</param>
/// <param name="Audiences">The token's <c>aud</c> values.</param>
/// <param name="Scopes">The token's scopes.</param>
public sealed record IntrospectionContext(
    string CallerClientId,
    string TokenClientId,
    string? Subject,
    IReadOnlyList<string> Audiences,
    IReadOnlyList<string> Scopes);

/// <summary>Input to <see cref="ProviderOptions.AuthorizeJwtBearerSubject"/> (RFC 7523).</summary>
/// <param name="ClientId">The authenticated client presenting the assertion.</param>
/// <param name="Subject">The <c>sub</c> asserted by the client, or <c>null</c>.</param>
/// <param name="RequestedScopes">Scopes that would be granted.</param>
public sealed record JwtBearerContext(
    string ClientId,
    string? Subject,
    IReadOnlyList<string> RequestedScopes);
