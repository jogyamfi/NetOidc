using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using Microsoft.Net.Http.Headers;
using NetOidc.Provider.Configuration;
using NetOidc.Provider.Errors;

namespace NetOidc.Provider.Http;

/// <summary>
/// Request and response rules shared by every protocol endpoint:
/// <list type="bullet">
/// <item>Responses carry <c>Cache-Control: no-store</c> (RFC 6749 §5.1, OIDC Core §3.1.3.3),
/// except the public metadata documents, which may be cached.</item>
/// <item>A form body that cannot be decoded is an <c>invalid_request</c>, not a server error.</item>
/// <item>Parameters must not be repeated (RFC 6749 §3.1, §3.2), except <c>resource</c>
/// (RFC 8707) and <c>audience</c> (RFC 8693).</item>
/// </list>
/// </summary>
internal static class ProtocolRequestFilter
{
    private static readonly HashSet<string> RepeatableParameters = new(StringComparer.Ordinal) { "resource", "audience" };

    public static async ValueTask<object?> InvokeAsync(EndpointFilterInvocationContext ctx, EndpointFilterDelegate next)
    {
        var http = ctx.HttpContext;
        var options = http.RequestServices.GetService(typeof(IOptions<ProviderOptions>)) is IOptions<ProviderOptions> o
            ? o.Value
            : new ProviderOptions();

        if (!IsMetadataEndpoint(http.Request.Path, options))
        {
            http.Response.OnStarting(static state =>
            {
                var headers = ((HttpResponse)state).Headers;
                if (!headers.ContainsKey(HeaderNames.CacheControl))
                {
                    headers.CacheControl = "no-store";
                    headers.Pragma = "no-cache";
                }
                return Task.CompletedTask;
            }, http.Response);
        }

        var error = await ValidateParametersAsync(http.Request);
        if (error is not null)
        {
            var browserFacing = http.Request.Path == options.AuthorizationEndpoint ||
                                http.Request.Path == options.EndSessionEndpoint;
            if (browserFacing && options.RenderErrorPage is { } render)
                return await render(http, error);
            return Results.BadRequest(error);
        }

        return await next(ctx);
    }

    private static bool IsMetadataEndpoint(PathString path, ProviderOptions options) =>
        path == options.DiscoveryEndpoint ||
        path == options.JwksEndpoint ||
        path == "/.well-known/openid-federation" ||
        path == "/.well-known/openid-credential-issuer";

    private static async Task<OAuthError?> ValidateParametersAsync(HttpRequest request)
    {
        if (FindRepeated(request.Query) is { } queryKey)
            return OAuthError.InvalidRequest($"parameter '{queryKey}' is included more than once");

        if (!HttpMethods.IsPost(request.Method) || !request.HasFormContentType)
            return null;

        IFormCollection form;
        try
        {
            form = await request.ReadFormAsync(request.HttpContext.RequestAborted);
        }
        catch (Exception ex) when (ex is InvalidDataException or BadHttpRequestException)
        {
            // Undecodable input (e.g. %00) or a body over the configured form limits.
            return OAuthError.InvalidRequest("the request body could not be parsed");
        }

        return FindRepeated(form) is { } formKey
            ? OAuthError.InvalidRequest($"parameter '{formKey}' is included more than once")
            : null;
    }

    private static string? FindRepeated(IEnumerable<KeyValuePair<string, Microsoft.Extensions.Primitives.StringValues>> values) =>
        values.FirstOrDefault(kv => kv.Value.Count > 1 && !RepeatableParameters.Contains(kv.Key)).Key;
}
