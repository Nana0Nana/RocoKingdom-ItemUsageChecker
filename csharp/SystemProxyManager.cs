using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text.Json.Serialization;
using Microsoft.Win32;

namespace RocoKingdom.ItemUsageChecker;

[SupportedOSPlatform("windows")]
public static class SystemProxyManager
{
    private const string RegPath = @"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
    private const int INTERNET_OPTION_SETTINGS_CHANGED = 39;
    private const int INTERNET_OPTION_REFRESH = 37;

    private static readonly string[] InterestingKeys =
    {
        "ProxyEnable", "ProxyServer", "ProxyOverride", "AutoConfigURL", "AutoDetect"
    };

    public sealed class RegistryValue
    {
        [JsonPropertyName("exists")]
        public bool Exists { get; set; }

        [JsonPropertyName("value")]
        public object? Value { get; set; }

        [JsonPropertyName("type")]
        public int Type { get; set; }

        [JsonIgnore]
        public RegistryValueKind Kind
        {
            get => (RegistryValueKind)Type;
            set => Type = (int)value;
        }
    }

    public sealed class ProxyState : Dictionary<string, RegistryValue> { }

    public static ProxyState ReadState()
    {
        var state = new ProxyState();
        using var key = Registry.CurrentUser.OpenSubKey(RegPath, writable: false)
            ?? throw new InvalidOperationException($"Cannot open registry key: {RegPath}");

        foreach (var name in InterestingKeys)
        {
            var value = key.GetValue(name, defaultValue: null, RegistryValueOptions.DoNotExpandEnvironmentNames);
            if (value == null)
            {
                state[name] = new RegistryValue { Exists = false, Value = null, Kind = RegistryValueKind.Unknown };
            }
            else
            {
                state[name] = new RegistryValue
                {
                    Exists = true,
                    Value = value,
                    Kind = key.GetValueKind(name),
                };
            }
        }
        return state;
    }

    public static void SetDirectProxy(string proxyServer)
    {
        using var key = Registry.CurrentUser.OpenSubKey(RegPath, writable: true)
            ?? throw new InvalidOperationException($"Cannot open registry key: {RegPath}");

        key.SetValue("AutoDetect", 0, RegistryValueKind.DWord);
        DeleteValueIfExists(key, "AutoConfigURL");
        key.SetValue("ProxyEnable", 1, RegistryValueKind.DWord);
        key.SetValue("ProxyServer", proxyServer, RegistryValueKind.String);
        key.SetValue("ProxyOverride", "<local>", RegistryValueKind.String);
        InternetSetOption();
    }

    public static void RestoreState(ProxyState state)
    {
        using var key = Registry.CurrentUser.OpenSubKey(RegPath, writable: true)
            ?? throw new InvalidOperationException($"Cannot open registry key: {RegPath}");

        foreach (var (name, item) in state)
        {
            if (item.Exists && item.Value != null && item.Kind != RegistryValueKind.Unknown)
            {
                key.SetValue(name, item.Value, item.Kind);
            }
            else
            {
                DeleteValueIfExists(key, name);
            }
        }
        InternetSetOption();
    }

    public static void VerifyDirectProxy(string proxyServer, int retries = 10, int delayMs = 500)
    {
        Exception? lastError = null;
        for (int i = 0; i < retries; i++)
        {
            try
            {
                var state = ReadState();
                var autoConfigUrl = state["AutoConfigURL"].Exists ? state["AutoConfigURL"].Value as string : null;
                var proxyEnable = state["ProxyEnable"].Exists ? Convert.ToInt32(state["ProxyEnable"].Value) : 0;
                var currentProxy = state["ProxyServer"].Exists ? state["ProxyServer"].Value as string : null;

                if (!string.IsNullOrEmpty(autoConfigUrl))
                    throw new InvalidOperationException($"AutoConfigURL 应为空，实际为 {autoConfigUrl}");
                if (proxyEnable != 1)
                    throw new InvalidOperationException($"ProxyEnable 应为 1，实际为 {proxyEnable}");
                if (!string.Equals(currentProxy, proxyServer, StringComparison.Ordinal))
                    throw new InvalidOperationException($"ProxyServer 未生效: {currentProxy}");

                return;
            }
            catch (Exception ex)
            {
                lastError = ex;
                Thread.Sleep(delayMs);
            }
        }
        throw new InvalidOperationException($"系统直连代理未确认生效: {lastError?.Message}");
    }

    private static void DeleteValueIfExists(RegistryKey key, string name)
    {
        try
        {
            key.DeleteValue(name, throwOnMissingValue: false);
        }
        catch
        {
            // ignore
        }
    }

    private static void InternetSetOption()
    {
        InternetSetOption(IntPtr.Zero, INTERNET_OPTION_SETTINGS_CHANGED, IntPtr.Zero, 0);
        InternetSetOption(IntPtr.Zero, INTERNET_OPTION_REFRESH, IntPtr.Zero, 0);
    }

    [DllImport("wininet.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool InternetSetOption(IntPtr hInternet, int dwOption, IntPtr lpBuffer, int dwBufferLength);
}
