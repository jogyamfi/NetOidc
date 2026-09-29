namespace NetOidc.Provider.Dcr;

/// <summary>
/// Thrown from <see cref="Configuration.ProviderOptions.ValidateDynamicClient"/> to reject a
/// registration. Its message is returned to the registering client as the
/// <c>error_description</c> of an <c>invalid_client_metadata</c> error, so it must not contain
/// internal details. Any other exception is reported generically and logged.
/// </summary>
public sealed class ClientMetadataValidationException(string message) : Exception(message);
