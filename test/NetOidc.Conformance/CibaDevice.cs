using NetOidc.Provider.Ciba;

namespace NetOidc.Conformance;

/// <summary>
/// Stands in for the End-User's authentication device in the FAPI-CIBA profile: every
/// backchannel authentication request is approved for the conformance user shortly after it
/// arrives, as if the user had accepted it on their phone.
/// </summary>
internal static class CibaDevice
{
    public static IServiceProvider? Services { get; set; }

    public static void ApproveLater(string authReqId) => _ = Task.Run(async () =>
    {
        await Task.Delay(TimeSpan.FromSeconds(3));
        if (Services?.GetService(typeof(ICibaService)) is ICibaService ciba)
            await ciba.CompleteAsync(authReqId, approve: true, subject: ConformanceUser.Subject);
    });
}
